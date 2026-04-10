package com.example.yono_shield

// ============================================================================
// YONO SHIELD — MainActivity.kt (v4 — Trojan Overlay Detection)
// ============================================================================
//
// The central bridge between Flutter UI and Native Kotlin security services.
//
// This activity sets up:
//   1. MethodChannel "com.yonoshield.security/bridge"
//      - Handles synchronous requests from Flutter (scan apps, verify security, etc.)
//
//   2. EventChannel "com.yonoshield.security/sms_stream"
//      - Streams intercepted SMS messages to Flutter in real-time
//
// SECURITY PIPELINE (verifyAppSecurity):
//   Gate 1: isDeviceRooted()       → Root detection
//   Gate 2: scanForTrojans()       → Behavioral permission audit (overlay trojans)
//   Gate 3: getAppSignatureHash()  → SHA-256 certificate extraction
//   Gate 4: Hash comparison        → Verify against official hash
//
// METHODS:
//   "isDeviceRooted"         → Checks for common root indicators
//   "scanForTrojans"         → Behavioral permission audit for trojan overlays
//   "getAppSignatureHash"    → SHA-256 cert fingerprint for a given package
//   "verifyAppSecurity"      → Master: root → trojan → signature pipeline
//   "scanInstalledApps"      → Full app scan with risk levels
//   "getInstalledPackages"   → Returns user-installed package info
//   "verifyAppSignature"     → Legacy signature verification
//   "showBlockOverlay"       → Starts the blocking overlay service
//   "dismissBlockOverlay"    → Stops the blocking overlay service
//   "checkOverlayPermission" → SYSTEM_ALERT_WINDOW check
//   "requestOverlayPermission"→ Opens system settings for overlay
//   "checkSmsPermission"     → RECEIVE_SMS check
//   "requestSmsPermission"   → Runtime SMS permission request
// ============================================================================

import android.Manifest
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.security.MessageDigest

class MainActivity : FlutterActivity() {

    companion object {
        private const val TAG = "YonoShield:Main"

        // Channel names — must match exactly in Flutter's SecurityBridge
        private const val METHOD_CHANNEL = "com.yonoshield.security/bridge"
        private const val EVENT_CHANNEL = "com.yonoshield.security/sms_stream"

        // Permission request codes
        private const val SMS_PERMISSION_REQUEST = 2001
        private const val OVERLAY_PERMISSION_REQUEST = 2002

        // ====================================================================
        // LAYER 3 — CRYPTOGRAPHIC GATEKEEPER CONFIG
        // ====================================================================
        // Mock official SHA-256 hash for demonstration.
        // In production, this would be fetched from a secure remote database
        // of known-good signing certificate fingerprints.
        // ====================================================================
        private const val OFFICIAL_HASH = "mock_sbi_hash_123"

        // Paths where the `su` binary is commonly found on rooted devices
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
    }

    // Pending MethodChannel result for async permission callbacks
    private var pendingSmsPermissionResult: MethodChannel.Result? = null

    // ========================================================================
    // LAYER 3 — CRYPTOGRAPHIC GATEKEEPER FUNCTIONS
    // ========================================================================

    /**
     * isDeviceRooted()
     *
     * Checks for common root indicators on the device:
     *   1. Build tags containing "test-keys" (custom ROM / unofficial build)
     *   2. Existence of `su` binary in well-known filesystem paths
     *   3. Presence of known root management packages (Magisk, SuperSU, etc.)
     *
     * @return true if any root indicator is found, false otherwise.
     */
    private fun isDeviceRooted(): Boolean {
        // CHECK 1: Build tags — "test-keys" indicates a non-release build
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            Log.w(TAG, "Root indicator: Build.TAGS contains 'test-keys'")
            return true
        }

        // CHECK 2: Probe for `su` binary in standard paths
        for (path in SU_PATHS) {
            try {
                if (File(path).exists()) {
                    Log.w(TAG, "Root indicator: su binary found at $path")
                    return true
                }
            } catch (e: SecurityException) {
                // Access denied — path may still exist, but we cannot confirm
                Log.d(TAG, "SecurityException checking $path: ${e.message}")
            }
        }

        // CHECK 3: Check for known root management app packages
        val rootPackages = arrayOf(
            "com.topjohnwu.magisk",          // Magisk Manager
            "eu.chainfire.supersu",           // SuperSU
            "com.koushikdutta.superuser",     // Superuser (CyanogenMod)
            "com.noshufou.android.su",        // Superuser (legacy)
            "com.thirdparty.superuser",       // Third-party superuser
            "com.yellowes.su",                // Another su variant
            "com.devadvance.rootcloak",       // RootCloak (hides root)
            "com.devadvance.rootcloakplus",   // RootCloak+
            "de.robv.android.xposed.installer", // Xposed Framework
            "com.saurik.substrate"            // Cydia Substrate
        )
        val pm = packageManager
        for (pkg in rootPackages) {
            try {
                pm.getPackageInfo(pkg, 0)
                Log.w(TAG, "Root indicator: root management package found: $pkg")
                return true
            } catch (e: PackageManager.NameNotFoundException) {
                // Package not installed — continue checking
            }
        }

        Log.d(TAG, "Root check passed: no root indicators found")
        return false
    }

    /**
     * scanForTrojans()
     *
     * Behavioral permission audit — detects the "Trojan Overlay" attack vector.
     *
     * Scammers disguise malware as harmless apps ("Candy Crush", "PDF Scanner")
     * that request dangerous overlay and SMS permissions. These apps wait for
     * the user to open a real banking app, then draw a fake login screen over it
     * to steal credentials.
     *
     * Detection heuristic — flags any NON-SYSTEM app that holds:
     *   Combo A: SYSTEM_ALERT_WINDOW + RECEIVE_SMS
     *     (can draw overlays AND intercept OTPs)
     *   OR
     *   Combo B: BIND_ACCESSIBILITY_SERVICE
     *     (can read screen content and inject taps — full overlay control)
     *
     * System apps (ApplicationInfo.FLAG_SYSTEM) are excluded to prevent
     * false positives from pre-installed OEM and Google services.
     *
     * @return The user-facing app name of the first trojan detected, or null if clean.
     */
    private fun scanForTrojans(): String? {
        val pm = packageManager

        // Get all installed packages WITH their requested permissions
        val allPackages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }

        Log.d(TAG, "scanForTrojans: scanning ${allPackages.size} packages")

        for (pkgInfo in allPackages) {
            // Skip system apps to prevent false positives
            val appInfo = pkgInfo.applicationInfo ?: continue
            if ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0) {
                continue
            }

            // Safely get requested permissions (may be null)
            val permissions = pkgInfo.requestedPermissions ?: continue
            val permSet = permissions.toSet()

            val hasOverlay = permSet.contains(Manifest.permission.SYSTEM_ALERT_WINDOW)
            val hasSms = permSet.contains(Manifest.permission.RECEIVE_SMS)
            val hasAccessibility = permSet.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")

            // COMBO A: Overlay + SMS — can draw fake screens AND intercept OTPs
            val comboA = hasOverlay && hasSms

            // COMBO B: Accessibility — can read screen, inject taps, full control
            val comboB = hasAccessibility

            if (comboA || comboB) {
                val appName = pm.getApplicationLabel(appInfo).toString()
                val reason = when {
                    comboA && comboB -> "OVERLAY + SMS + ACCESSIBILITY"
                    comboA -> "OVERLAY + SMS"
                    else -> "ACCESSIBILITY"
                }
                Log.w(TAG, "⚠ TROJAN DETECTED: '$appName' (${pkgInfo.packageName})")
                Log.w(TAG, "  Dangerous combo: $reason")
                Log.w(TAG, "  Permissions: $permSet")
                return appName
            }
        }

        Log.d(TAG, "Trojan scan passed: no overlay trojans found")
        return null
    }

    /**
     * getAppSignatureHash(packageName)
     *
     * Extracts the first signing certificate of the given package and
     * computes its SHA-256 hex digest.
     *
     * Uses GET_SIGNING_CERTIFICATES on API 28+ (Android 9 Pie) and falls
     * back to the deprecated GET_SIGNATURES for older API levels.
     *
     * @param packageName The package name of the installed app.
     * @return The SHA-256 hex string of the signing certificate, or null
     *         if the package is not found or has no signatures.
     */
    private fun getAppSignatureHash(packageName: String): String? {
        return try {
            val sigBytes: ByteArray? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // API 28+ — Modern signing info API
                val packageInfo: PackageInfo = packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signingInfo = packageInfo.signingInfo
                if (signingInfo != null) {
                    if (signingInfo.hasMultipleSigners()) {
                        // Multiple signers — use the first APK signature
                        signingInfo.apkContentsSigners?.firstOrNull()?.toByteArray()
                    } else {
                        // Single signer — use the signing certificate history
                        signingInfo.signingCertificateHistory?.firstOrNull()?.toByteArray()
                    }
                } else {
                    null
                }
            } else {
                // API < 28 — Legacy signatures API
                @Suppress("DEPRECATION")
                val packageInfo: PackageInfo = packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES
                )
                @Suppress("DEPRECATION")
                packageInfo.signatures?.firstOrNull()?.toByteArray()
            }

            if (sigBytes != null) {
                // Compute SHA-256 digest
                val digest = MessageDigest.getInstance("SHA-256")
                val hashBytes = digest.digest(sigBytes)

                // Convert to hex string with colon separators (AA:BB:CC:...)
                val hexString = hashBytes.joinToString(":") { byte ->
                    String.format("%02X", byte)
                }
                Log.d(TAG, "SHA-256 hash for $packageName: $hexString")
                hexString
            } else {
                Log.w(TAG, "No signing certificate found for $packageName")
                null
            }
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(TAG, "Package not found: $packageName")
            null
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting signature hash for $packageName", e)
            null
        }
    }

    /**
     * verifyAppSecurity(targetPackageName)
     *
     * The master security pipeline. Orchestrates a 4-gate verification:
     *   Gate 1: Root detection  → "ROOTED_DEVICE"
     *   Gate 2: Trojan scan     → "TROJAN_DETECTED_{appName}"
     *   Gate 3: Cert extraction → "APP_NOT_FOUND"
     *   Gate 4: Hash comparison → "SAFE" or "INVALID_SIGNATURE"
     *
     * @param targetPackageName The package name of the app to verify.
     * @return Map with verdict, metadata, and human-readable message.
     */
    private fun verifyAppSecurity(targetPackageName: String): Map<String, Any?> {
        Log.d(TAG, "verifyAppSecurity() called for: $targetPackageName")

        // GATE 1: Root Detection
        val rooted = isDeviceRooted()
        if (rooted) {
            Log.w(TAG, "GATE 1 FAILED: Device is rooted")
            return mapOf(
                "verdict" to "ROOTED_DEVICE",
                "packageName" to targetPackageName,
                "isRooted" to true,
                "trojanApp" to null,
                "liveHash" to null,
                "expectedHash" to OFFICIAL_HASH,
                "message" to "Device OS compromised — root detected. YONO operations locked."
            )
        }
        Log.d(TAG, "GATE 1 PASSED: Device is not rooted")

        // GATE 2: Trojan Overlay Detection (Behavioral Permission Audit)
        val trojanAppName = scanForTrojans()
        if (trojanAppName != null) {
            Log.w(TAG, "GATE 2 FAILED: Trojan overlay detected — '$trojanAppName'")
            return mapOf(
                "verdict" to "TROJAN_DETECTED_$trojanAppName",
                "packageName" to targetPackageName,
                "isRooted" to false,
                "trojanApp" to trojanAppName,
                "liveHash" to null,
                "expectedHash" to OFFICIAL_HASH,
                "message" to "'$trojanAppName' has malicious screen-reading permissions. Uninstall immediately to unlock YONO."
            )
        }
        Log.d(TAG, "GATE 2 PASSED: No trojan overlays detected")

        // GATE 3: Signature Extraction
        val liveHash = getAppSignatureHash(targetPackageName)
        if (liveHash == null) {
            Log.w(TAG, "GATE 3: Target app not found or no signature: $targetPackageName")
            return mapOf(
                "verdict" to "APP_NOT_FOUND",
                "packageName" to targetPackageName,
                "isRooted" to false,
                "trojanApp" to null,
                "liveHash" to null,
                "expectedHash" to OFFICIAL_HASH,
                "message" to "Target application not installed on this device."
            )
        }

        // GATE 4: Hash Comparison
        val isMatch = liveHash.equals(OFFICIAL_HASH, ignoreCase = true)
        if (isMatch) {
            Log.d(TAG, "GATE 4 PASSED: Signature matches official hash")
            return mapOf(
                "verdict" to "SAFE",
                "packageName" to targetPackageName,
                "isRooted" to false,
                "trojanApp" to null,
                "liveHash" to liveHash,
                "expectedHash" to OFFICIAL_HASH,
                "message" to "System verified. Environment secure."
            )
        } else {
            Log.w(TAG, "GATE 4 FAILED: Signature mismatch!")
            Log.w(TAG, "  Live:     $liveHash")
            Log.w(TAG, "  Expected: $OFFICIAL_HASH")
            return mapOf(
                "verdict" to "INVALID_SIGNATURE",
                "packageName" to targetPackageName,
                "isRooted" to false,
                "trojanApp" to null,
                "liveHash" to liveHash,
                "expectedHash" to OFFICIAL_HASH,
                "message" to "Unofficial app signature detected. Brand impersonation blocked."
            )
        }
    }

    // ========================================================================
    // configureFlutterEngine()
    //
    // Called by the Flutter framework to initialize the engine. This is where
    // we register our MethodChannel and EventChannel handlers.
    // ========================================================================
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        Log.d(TAG, "Configuring Flutter engine — setting up security bridge channels")

        // ====================================================================
        // METHOD CHANNEL SETUP
        // Handles request/response calls from Flutter → Kotlin
        // ====================================================================
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
            .setMethodCallHandler { call, result ->
                Log.d(TAG, "MethodChannel call received: ${call.method}")

                when (call.method) {

                    // --------------------------------------------------------
                    // LAYER 3: Cryptographic Gatekeeper — Root Detection
                    // --------------------------------------------------------
                    "isDeviceRooted" -> {
                        try {
                            val rooted = isDeviceRooted()
                            Log.d(TAG, "isDeviceRooted() → $rooted")
                            result.success(rooted)
                        } catch (e: Exception) {
                            Log.e(TAG, "Root detection failed", e)
                            result.error("ROOT_CHECK_ERROR", "Root detection failed: ${e.message}", null)
                        }
                    }

                    // --------------------------------------------------------
                    // LAYER 3: Cryptographic Gatekeeper — Signature Hash
                    // --------------------------------------------------------
                    "getAppSignatureHash" -> {
                        val packageName = call.argument<String>("packageName")
                        if (packageName == null) {
                            result.error("INVALID_ARGS", "packageName argument is required", null)
                            return@setMethodCallHandler
                        }
                        try {
                            val hash = getAppSignatureHash(packageName)
                            Log.d(TAG, "getAppSignatureHash($packageName) → $hash")
                            result.success(hash)
                        } catch (e: Exception) {
                            Log.e(TAG, "Signature hash extraction failed", e)
                            result.error("HASH_ERROR", "Hash extraction failed: ${e.message}", null)
                        }
                    }

                    // --------------------------------------------------------
                    // LAYER 4: Trojan Overlay Detection — Standalone scan
                    // --------------------------------------------------------
                    "scanForTrojans" -> {
                        try {
                            val trojanApp = scanForTrojans()
                            Log.d(TAG, "scanForTrojans() → $trojanApp")
                            result.success(trojanApp)
                        } catch (e: Exception) {
                            Log.e(TAG, "Trojan scan failed", e)
                            result.error("TROJAN_SCAN_ERROR", "Trojan scan failed: ${e.message}", null)
                        }
                    }

                    // --------------------------------------------------------
                    // MASTER PIPELINE: Root → Trojan → Signature Verify
                    // --------------------------------------------------------
                    "verifyAppSecurity" -> {
                        val packageName = call.argument<String>("packageName")
                        if (packageName == null) {
                            result.error("INVALID_ARGS", "packageName argument is required", null)
                            return@setMethodCallHandler
                        }
                        try {
                            val securityResult = verifyAppSecurity(packageName)
                            Log.d(TAG, "verifyAppSecurity($packageName) → ${securityResult["verdict"]}")
                            result.success(securityResult)
                        } catch (e: Exception) {
                            Log.e(TAG, "Security verification failed", e)
                            result.error("VERIFY_ERROR", "Security verification failed: ${e.message}", null)
                        }
                    }

                    // --------------------------------------------------------
                    // PILLAR 1: Clone Radar — Get installed packages list
                    // --------------------------------------------------------
                    "getInstalledPackages" -> {
                        try {
                            val pm = packageManager
                            val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                            val packages = installedApps
                                .filter { appInfo ->
                                    // Only include user-installed (non-system) apps
                                    (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0
                                }
                                .map { appInfo ->
                                    mapOf(
                                        "packageName" to appInfo.packageName,
                                        "appName" to pm.getApplicationLabel(appInfo).toString()
                                    )
                                }
                            Log.d(TAG, "getInstalledPackages: ${packages.size} user apps found")
                            result.success(packages)
                        } catch (e: Exception) {
                            Log.e(TAG, "getInstalledPackages failed", e)
                            result.error("SCAN_ERROR", "Failed to get installed packages: ${e.message}", null)
                        }
                    }

                    // --------------------------------------------------------
                    // PILLAR 1: Clone Radar — Legacy verify signature
                    // --------------------------------------------------------
                    "verifyAppSignature" -> {
                        val packageName = call.argument<String>("packageName")
                        if (packageName == null) {
                            result.error("INVALID_ARGS", "packageName argument is required", null)
                            return@setMethodCallHandler
                        }
                        try {
                            val liveHash = getAppSignatureHash(packageName)
                            val pm = packageManager
                            val appName = try {
                                val appInfo = pm.getApplicationInfo(packageName, 0)
                                pm.getApplicationLabel(appInfo).toString()
                            } catch (e: Exception) { packageName }

                            val isMatch = liveHash != null && liveHash.equals(OFFICIAL_HASH, ignoreCase = true)

                            result.success(mapOf(
                                "packageName" to packageName,
                                "appName" to appName,
                                "isVerified" to isMatch,
                                "liveHash" to (liveHash ?: "NOT_FOUND"),
                                "expectedHash" to OFFICIAL_HASH,
                                "verdict" to if (liveHash == null) "APP_NOT_FOUND"
                                             else if (isMatch) "SIGNATURE_MATCH"
                                             else "SIGNATURE_MISMATCH"
                            ))
                        } catch (e: Exception) {
                            Log.e(TAG, "verifyAppSignature failed", e)
                            result.error("VERIFY_ERROR", "Signature verification failed: ${e.message}", null)
                        }
                    }

                    // --------------------------------------------------------
                    // PILLAR 1: Clone Radar — Full app scan
                    // --------------------------------------------------------
                    "scanInstalledApps" -> {
                        try {
                            val scanner = PackageScannerService(this)
                            val apps = scanner.scanAllApps()
                            Log.d(TAG, "Scan complete: ${apps.size} apps found")
                            result.success(apps)
                        } catch (e: Exception) {
                            Log.e(TAG, "Package scan failed", e)
                            result.error(
                                "SCAN_ERROR",
                                "Failed to scan installed applications: ${e.message}",
                                null
                            )
                        }
                    }

                    // --------------------------------------------------------
                    // PILLAR 3: Block Overlay — Show the blocking screen
                    // --------------------------------------------------------
                    "showBlockOverlay" -> {
                        if (!Settings.canDrawOverlays(this)) {
                            Log.w(TAG, "Overlay permission not granted")
                            result.error(
                                "PERMISSION_DENIED",
                                "SYSTEM_ALERT_WINDOW permission not granted. Call requestOverlayPermission() first.",
                                null
                            )
                            return@setMethodCallHandler
                        }

                        try {
                            val intent = Intent(this, OverlayService::class.java)
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                                startForegroundService(intent)
                            } else {
                                startService(intent)
                            }
                            Log.d(TAG, "OverlayService started successfully")
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to start OverlayService", e)
                            result.error("OVERLAY_ERROR", "Failed to show overlay: ${e.message}", null)
                        }
                    }

                    // --------------------------------------------------------
                    // PILLAR 3: Block Overlay — Dismiss the blocking screen
                    // --------------------------------------------------------
                    "dismissBlockOverlay" -> {
                        try {
                            val intent = Intent(this, OverlayService::class.java)
                            stopService(intent)
                            Log.d(TAG, "OverlayService stopped")
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to stop OverlayService", e)
                            result.error("OVERLAY_ERROR", "Failed to dismiss overlay: ${e.message}", null)
                        }
                    }

                    // --------------------------------------------------------
                    // PERMISSION: Check if SYSTEM_ALERT_WINDOW is granted
                    // --------------------------------------------------------
                    "checkOverlayPermission" -> {
                        val granted = Settings.canDrawOverlays(this)
                        Log.d(TAG, "Overlay permission check: $granted")
                        result.success(granted)
                    }

                    // --------------------------------------------------------
                    // PERMISSION: Open system settings to grant overlay permission
                    // --------------------------------------------------------
                    "requestOverlayPermission" -> {
                        if (Settings.canDrawOverlays(this)) {
                            Log.d(TAG, "Overlay permission already granted")
                            result.success(true)
                            return@setMethodCallHandler
                        }

                        Log.d(TAG, "Requesting overlay permission — opening system settings")
                        val intent = Intent(
                            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                            Uri.parse("package:$packageName")
                        )
                        startActivityForResult(intent, OVERLAY_PERMISSION_REQUEST)
                        result.success(false)
                    }

                    // --------------------------------------------------------
                    // PERMISSION: Check if RECEIVE_SMS is granted
                    // --------------------------------------------------------
                    "checkSmsPermission" -> {
                        val granted = ContextCompat.checkSelfPermission(
                            this, Manifest.permission.RECEIVE_SMS
                        ) == PackageManager.PERMISSION_GRANTED
                        Log.d(TAG, "SMS permission check: $granted")
                        result.success(granted)
                    }

                    // --------------------------------------------------------
                    // PERMISSION: Request RECEIVE_SMS permission at runtime
                    // --------------------------------------------------------
                    "requestSmsPermission" -> {
                        if (ContextCompat.checkSelfPermission(
                                this, Manifest.permission.RECEIVE_SMS
                            ) == PackageManager.PERMISSION_GRANTED
                        ) {
                            Log.d(TAG, "SMS permission already granted")
                            result.success(true)
                            return@setMethodCallHandler
                        }

                        Log.d(TAG, "Requesting SMS permission at runtime")
                        pendingSmsPermissionResult = result
                        ActivityCompat.requestPermissions(
                            this,
                            arrayOf(
                                Manifest.permission.RECEIVE_SMS,
                                Manifest.permission.READ_SMS
                            ),
                            SMS_PERMISSION_REQUEST
                        )
                    }

                    // --------------------------------------------------------
                    // UNKNOWN METHOD — Return not implemented
                    // --------------------------------------------------------
                    else -> {
                        Log.w(TAG, "Unknown method call: ${call.method}")
                        result.notImplemented()
                    }
                }
            }

        // ====================================================================
        // EVENT CHANNEL SETUP
        // Streams intercepted SMS messages from Kotlin → Flutter in real-time
        // ====================================================================
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {

                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    Log.d(TAG, "Flutter is now listening for SMS events")
                    SmsReceiver.eventSink = events
                }

                override fun onCancel(arguments: Any?) {
                    Log.d(TAG, "Flutter stopped listening for SMS events")
                    SmsReceiver.eventSink = null
                }
            })

        Log.d(TAG, "Security bridge channels configured successfully (v4 — Trojan Overlay Detection)")
    }

    // ========================================================================
    // onRequestPermissionsResult()
    // ========================================================================
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        when (requestCode) {
            SMS_PERMISSION_REQUEST -> {
                val granted = grantResults.isNotEmpty() &&
                        grantResults[0] == PackageManager.PERMISSION_GRANTED
                Log.d(TAG, "SMS permission result: $granted")
                pendingSmsPermissionResult?.success(granted)
                pendingSmsPermissionResult = null
            }
        }
    }

    // ========================================================================
    // onActivityResult()
    // ========================================================================
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        when (requestCode) {
            OVERLAY_PERMISSION_REQUEST -> {
                val granted = Settings.canDrawOverlays(this)
                Log.d(TAG, "Overlay permission result: $granted")
            }
        }
    }
}
