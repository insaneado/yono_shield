package com.example.yono_shield

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.io.File
import java.security.MessageDigest

class SecurityManager(private val context: Context) {

    private data class TrojanCandidate(
        val appName: String,
        val packageName: String
    )

    companion object {
        private const val TAG = "YonoShield:Security"

        // ── KNOWN-GOOD SIGNING CERTIFICATE HASHES ──
        // Each entry maps a package name to the SHA-256 fingerprint of its
        // official signing certificate.  The gatekeeper compares the LIVE
        // hash extracted from the device against this registry.
        //
        // HOW TO ADD A NEW APP:
        //   1. Install the official app from the Play Store
        //   2. Run: keytool -printcert -jarfile <apk> | grep SHA256
        //      — or — let the gatekeeper scan it (the live hash is returned
        //      in the result map) and copy that value here.
        //   3. Add the entry below in UPPER-CASE colon-separated hex format.
        //
        // PRODUCTION: This registry should be fetched from a secure backend
        //   endpoint and cached locally, not hardcoded in the APK.
        private val KNOWN_GOOD_HASHES: Map<String, String> = mapOf(
            // Official SBI YONO (replace with real hash from production APK)
            "com.sbi.SBIFreedomPlus" to "PASTE_REAL_SHA256_HERE",
            // Demo/test target used during development
            "com.sbi.fakeyono" to "DEMO_TARGET_NO_HASH"
        )

        // Fallback for legacy callers that still reference a single hash
        private val OFFICIAL_HASH: String
            get() = KNOWN_GOOD_HASHES.values.firstOrNull() ?: "NO_HASH_CONFIGURED"

        private val SU_PATHS = arrayOf(
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/su/bin/su",
            "/su/bin",
            "/vendor/bin/su"
        )

        private val ROOT_PACKAGES = arrayOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate"
        )
    }

    private val packageManager: PackageManager
        get() = context.packageManager

    fun isDeviceRooted(): Boolean {
        val buildTags = Build.TAGS
        if (!buildTags.isNullOrBlank() && buildTags.contains("test-keys")) {
            Log.w(TAG, "Root indicator: Build.TAGS contains test-keys")
            return true
        }

        for (path in SU_PATHS) {
            try {
                if (File(path).exists()) {
                    Log.w(TAG, "Root indicator: su binary found at $path")
                    return true
                }
            } catch (e: SecurityException) {
                Log.d(TAG, "Unable to inspect $path: ${e.message}")
            }
        }

        for (pkg in ROOT_PACKAGES) {
            try {
                getPackageInfoCompat(pkg, 0)
                Log.w(TAG, "Root indicator: root management package found: $pkg")
                return true
            } catch (_: PackageManager.NameNotFoundException) {
                // Package not installed; continue.
            }
        }

        Log.d(TAG, "Root check passed: no indicators found")
        return false
    }

    fun scanForTrojans(): String? {
        return scanForTrojanCandidate()?.appName
    }

    private fun scanForTrojanCandidate(): TrojanCandidate? {
        val allPackages = getInstalledPackagesCompat(
            PackageManager.GET_PERMISSIONS.toLong() or PackageManager.GET_SERVICES.toLong()
        )

        Log.d(TAG, "scanForTrojans: scanning ${allPackages.size} packages")

        for (pkgInfo in allPackages) {
            val appInfo = pkgInfo.applicationInfo ?: continue
            val isSystemApp =
                (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

            if (isSystemApp || pkgInfo.packageName == context.packageName) {
                continue
            }

            val requestedPermissions = pkgInfo.requestedPermissions?.toSet() ?: emptySet()
            val hasOverlay = requestedPermissions.contains(Manifest.permission.SYSTEM_ALERT_WINDOW)
            val hasSms = requestedPermissions.contains(Manifest.permission.RECEIVE_SMS)
            val hasAccessibilityService =
                pkgInfo.services?.any {
                    it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE
                } == true

            val hasOverlaySmsCombo = hasOverlay && hasSms
            if (!hasOverlaySmsCombo && !hasAccessibilityService) {
                continue
            }

            val appName = packageManager.getApplicationLabel(appInfo).toString().ifBlank {
                pkgInfo.packageName
            }
            val reason = when {
                hasOverlaySmsCombo && hasAccessibilityService -> "OVERLAY + SMS + ACCESSIBILITY"
                hasOverlaySmsCombo -> "OVERLAY + SMS"
                else -> "ACCESSIBILITY"
            }

            Log.w(TAG, "TROJAN DETECTED: '$appName' (${pkgInfo.packageName})")
            Log.w(TAG, "Dangerous combo: $reason")
            Log.w(TAG, "Requested permissions: $requestedPermissions")
            return TrojanCandidate(
                appName = appName,
                packageName = pkgInfo.packageName
            )
        }

        Log.d(TAG, "Trojan scan passed: no overlay trojans found")
        return null
    }

    fun getAppSignatureHash(packageName: String): String? {
        return try {
            val sigBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = getPackageInfoCompat(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES.toLong()
                )
                val signingInfo = packageInfo.signingInfo
                if (signingInfo?.hasMultipleSigners() == true) {
                    signingInfo.apkContentsSigners?.firstOrNull()?.toByteArray()
                } else {
                    signingInfo?.signingCertificateHistory?.firstOrNull()?.toByteArray()
                }
            } else {
                @Suppress("DEPRECATION")
                getPackageInfoCompat(packageName, PackageManager.GET_SIGNATURES.toLong())
                    .signatures
                    ?.firstOrNull()
                    ?.toByteArray()
            }

            if (sigBytes == null) {
                Log.w(TAG, "No signing certificate found for $packageName")
                return null
            }

            val digest = MessageDigest.getInstance("SHA-256")
            val hashBytes = digest.digest(sigBytes)
            val hexString = hashBytes.joinToString(":") { byte ->
                String.format("%02X", byte)
            }

            Log.d(TAG, "SHA-256 hash for $packageName: $hexString")
            hexString
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(TAG, "Package not found: $packageName")
            null
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting signature hash for $packageName", e)
            null
        }
    }

    fun verifyAppSecurity(targetPackageName: String): Any {
        Log.d(TAG, "verifyAppSecurity() called for: $targetPackageName")

        if (isDeviceRooted()) {
            Log.w(TAG, "Gate 1 failed: rooted device")
            return "ROOTED_DEVICE"
        }

        val trojanCandidate = scanForTrojanCandidate()
        if (trojanCandidate != null) {
            val verdict = "TROJAN_DETECTED_${trojanCandidate.appName}"
            Log.w(TAG, "Gate 2 failed: $verdict")
            return mapOf(
                "verdict" to verdict,
                "packageName" to trojanCandidate.packageName,
                "isRooted" to false,
                "trojanApp" to trojanCandidate.appName,
                "trojanPackage" to trojanCandidate.packageName,
                "liveHash" to null,
                "expectedHash" to OFFICIAL_HASH,
                "message" to "'${trojanCandidate.appName}' has malicious screen-reading permissions. Uninstall immediately to unlock YONO."
            )
        }

        return verifySignatureStage(targetPackageName)
    }

    fun verifyAppSignature(packageName: String): Map<String, Any?> {
        val liveHash = getAppSignatureHash(packageName)
        val appName = try {
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            packageManager.getApplicationLabel(appInfo).toString()
        } catch (_: Exception) {
            packageName
        }

        val isMatch = liveHash != null && liveHash.equals(OFFICIAL_HASH, ignoreCase = true)

        return mapOf(
            "packageName" to packageName,
            "appName" to appName,
            "isVerified" to isMatch,
            "liveHash" to (liveHash ?: "NOT_FOUND"),
            "expectedHash" to OFFICIAL_HASH,
            "verdict" to when {
                liveHash == null -> "APP_NOT_FOUND"
                isMatch -> "SIGNATURE_MATCH"
                else -> "SIGNATURE_MISMATCH"
            }
        )
    }

    private fun verifySignatureStage(targetPackageName: String): Map<String, Any?> {
        val liveHash = getAppSignatureHash(targetPackageName)
        // Resolve expected hash from the per-package registry
        val expectedHash = KNOWN_GOOD_HASHES[targetPackageName]

        if (liveHash == null) {
            Log.w(TAG, "Gate 3 failed: app not found or signature unavailable")
            return mapOf(
                "verdict" to "APP_NOT_FOUND",
                "packageName" to targetPackageName,
                "isRooted" to false,
                "trojanApp" to null,
                "liveHash" to null,
                "expectedHash" to (expectedHash ?: "NOT_IN_REGISTRY"),
                "message" to "Target application not installed on this device."
            )
        }

        // If the package isn't in our registry, we can't verify — report live hash
        if (expectedHash == null || expectedHash == "PASTE_REAL_SHA256_HERE" || expectedHash == "DEMO_TARGET_NO_HASH") {
            Log.d(TAG, "Gate 4: package $targetPackageName not in hash registry, returning live hash for reference")
            return mapOf(
                "verdict" to "SAFE",
                "packageName" to targetPackageName,
                "isRooted" to false,
                "trojanApp" to null,
                "liveHash" to liveHash,
                "expectedHash" to (expectedHash ?: "NOT_IN_REGISTRY"),
                "message" to "App signature extracted. No known-good hash in registry to compare against."
            )
        }

        val isMatch = liveHash.equals(expectedHash, ignoreCase = true)
        if (isMatch) {
            Log.d(TAG, "Gate 4 passed: signature matches official hash")
            return mapOf(
                "verdict" to "SAFE",
                "packageName" to targetPackageName,
                "isRooted" to false,
                "trojanApp" to null,
                "liveHash" to liveHash,
                "expectedHash" to expectedHash,
                "message" to "System verified. Environment secure."
            )
        }

        Log.w(TAG, "Gate 4 failed: signature mismatch")
        Log.w(TAG, "Live: $liveHash")
        Log.w(TAG, "Expected: $expectedHash")
        return mapOf(
            "verdict" to "INVALID_SIGNATURE",
            "packageName" to targetPackageName,
            "isRooted" to false,
            "trojanApp" to null,
            "liveHash" to liveHash,
            "expectedHash" to expectedHash,
            "message" to "Unofficial app signature detected. Brand impersonation blocked."
        )
    }

    private fun getInstalledPackagesCompat(flags: Long): List<PackageInfo> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledPackages(flags.toInt())
        }
    }

    private fun getPackageInfoCompat(packageName: String, flags: Long): PackageInfo {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, flags.toInt())
        }
    }
}
