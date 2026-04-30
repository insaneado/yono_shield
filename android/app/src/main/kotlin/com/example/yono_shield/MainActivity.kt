package com.example.yono_shield

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.InstallSourceInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Base64
import android.util.Log
import android.view.accessibility.AccessibilityManager
import android.view.WindowManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import org.json.JSONObject
import java.security.MessageDigest

class MainActivity : FlutterActivity() {

    companion object {
        private const val TAG = "YonoShield:Main"
        private const val METHOD_CHANNEL = "com.yonoshield.security/bridge"
        private const val EVENT_CHANNEL = "com.yonoshield.security/sms_stream"
        private const val ACCESSIBILITY_CHANNEL = "kavach.security/accessibility"
        private const val NOTIFICATION_CHANNEL = "kavach.security/notifications"
        private const val INTEGRITY_CHANNEL = "kavach.security/integrity"
        private const val SMS_PERMISSION_REQUEST = 2001
        private const val OVERLAY_PERMISSION_REQUEST = 2002

        // ── Installer Verification ──
        // Any accessibility service installed by a trusted store is allowed.
        // Sideloaded APKs (null / packageinstaller / file-manager) are flagged.
        private val TRUSTED_INSTALLERS = setOf(
            "com.android.vending",            // Google Play Store
            "com.huawei.appmarket",            // Huawei AppGallery
            "com.samsung.android.vending",     // Samsung Galaxy Store
            "com.xiaomi.market",               // Xiaomi GetApps
            "com.oppo.market",                 // OPPO App Market
            "com.heytap.market"                // OnePlus / realme Store
        )

        // ── Google Cloud Project Number ──
        // Required by Play Integrity API to identify your app's GCP project.
        // HOW TO GET THIS:
        //   1. Go to https://console.cloud.google.com/
        //   2. Enable the "Play Integrity API" for your project
        //   3. Copy the numeric Project Number (NOT the Project ID)
        //   4. Replace the placeholder below
        //
        // ⚠️ PRODUCTION: This should come from a server-side config endpoint,
        //    NOT be hardcoded in the APK where it can be extracted.
        private const val CLOUD_PROJECT_NUMBER: Long = 880368626361L
    }

    private val securityManager by lazy(LazyThreadSafetyMode.NONE) {
        SecurityManager(applicationContext)
    }

    private var pendingSmsPermissionResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        Log.d(TAG, "Configuring Flutter engine and native security bridge")

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
            .setMethodCallHandler { call, result ->
                Log.d(TAG, "MethodChannel call received: ${call.method}")

                when (call.method) {
                    "isDeviceRooted" -> {
                        try {
                            result.success(securityManager.isDeviceRooted())
                        } catch (e: Exception) {
                            Log.e(TAG, "Root detection failed", e)
                            result.error(
                                "ROOT_CHECK_ERROR",
                                "Root detection failed: ${e.message}",
                                null
                            )
                        }
                    }

                    "scanForTrojans" -> {
                        try {
                            result.success(securityManager.scanForTrojans())
                        } catch (e: Exception) {
                            Log.e(TAG, "Trojan scan failed", e)
                            result.error(
                                "TROJAN_SCAN_ERROR",
                                "Trojan scan failed: ${e.message}",
                                null
                            )
                        }
                    }

                    "getAppSignatureHash" -> {
                        val packageName = call.argument<String>("packageName")
                        if (packageName.isNullOrBlank()) {
                            result.error("INVALID_ARGS", "packageName argument is required", null)
                            return@setMethodCallHandler
                        }

                        try {
                            result.success(securityManager.getAppSignatureHash(packageName))
                        } catch (e: Exception) {
                            Log.e(TAG, "Signature hash extraction failed", e)
                            result.error(
                                "HASH_ERROR",
                                "Hash extraction failed: ${e.message}",
                                null
                            )
                        }
                    }

                    "verifyAppSecurity" -> {
                        val packageName = call.argument<String>("packageName")
                        if (packageName.isNullOrBlank()) {
                            result.error("INVALID_ARGS", "packageName argument is required", null)
                            return@setMethodCallHandler
                        }

                        try {
                            val securityResult = securityManager.verifyAppSecurity(packageName)
                            Log.d(
                                TAG,
                                "verifyAppSecurity($packageName) -> ${extractVerdict(securityResult)}"
                            )
                            result.success(securityResult)
                        } catch (e: Exception) {
                            Log.e(TAG, "Security verification failed", e)
                            result.error(
                                "VERIFY_ERROR",
                                "Security verification failed: ${e.message}",
                                null
                            )
                        }
                    }

                    "getInstalledPackages" -> {
                        try {
                            val pm = packageManager
                            val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                            val packages = installedApps
                                .filter { appInfo ->
                                    (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) == 0
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
                            result.error(
                                "SCAN_ERROR",
                                "Failed to get installed packages: ${e.message}",
                                null
                            )
                        }
                    }

                    "verifyAppSignature" -> {
                        val packageName = call.argument<String>("packageName")
                        if (packageName.isNullOrBlank()) {
                            result.error("INVALID_ARGS", "packageName argument is required", null)
                            return@setMethodCallHandler
                        }

                        try {
                            result.success(securityManager.verifyAppSignature(packageName))
                        } catch (e: Exception) {
                            Log.e(TAG, "verifyAppSignature failed", e)
                            result.error(
                                "VERIFY_ERROR",
                                "Signature verification failed: ${e.message}",
                                null
                            )
                        }
                    }

                    "uninstallApp" -> {
                        val packageName = call.argument<String>("packageName")
                        if (packageName.isNullOrBlank()) {
                            result.error("INVALID_ARGS", "packageName argument is required", null)
                            return@setMethodCallHandler
                        }

                        try {
                            val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                data = Uri.parse("package:$packageName")
                                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            }
                            startActivity(uninstallIntent)
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to launch uninstaller for $packageName", e)
                            result.error(
                                "UNINSTALL_ERROR",
                                "Failed to launch uninstaller: ${e.message}",
                                null
                            )
                        }
                    }

                    "scanInstalledApps" -> {
                        try {
                            val scanner = PackageScannerService(this)
                            result.success(scanner.scanAllApps())
                        } catch (e: Exception) {
                            Log.e(TAG, "Package scan failed", e)
                            result.error(
                                "SCAN_ERROR",
                                "Failed to scan installed applications: ${e.message}",
                                null
                            )
                        }
                    }

                    "showBlockOverlay" -> {
                        if (!Settings.canDrawOverlays(this)) {
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
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to start OverlayService", e)
                            result.error("OVERLAY_ERROR", "Failed to show overlay: ${e.message}", null)
                        }
                    }

                    "dismissBlockOverlay" -> {
                        try {
                            stopService(Intent(this, OverlayService::class.java))
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to stop OverlayService", e)
                            result.error(
                                "OVERLAY_ERROR",
                                "Failed to dismiss overlay: ${e.message}",
                                null
                            )
                        }
                    }

                    "checkOverlayPermission" -> {
                        result.success(Settings.canDrawOverlays(this))
                    }

                    "requestOverlayPermission" -> {
                        if (Settings.canDrawOverlays(this)) {
                            result.success(true)
                            return@setMethodCallHandler
                        }

                        val intent = Intent(
                            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                            Uri.parse("package:$packageName")
                        )
                        startActivityForResult(intent, OVERLAY_PERMISSION_REQUEST)
                        result.success(false)
                    }

                    "checkSmsPermission" -> {
                        val granted = ContextCompat.checkSelfPermission(
                            this,
                            Manifest.permission.RECEIVE_SMS
                        ) == PackageManager.PERMISSION_GRANTED
                        result.success(granted)
                    }

                    "requestSmsPermission" -> {
                        if (ContextCompat.checkSelfPermission(
                                this,
                                Manifest.permission.RECEIVE_SMS
                            ) == PackageManager.PERMISSION_GRANTED
                        ) {
                            result.success(true)
                            return@setMethodCallHandler
                        }

                        pendingSmsPermissionResult = result
                        ActivityCompat.requestPermissions(
                            this,
                            arrayOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS),
                            SMS_PERMISSION_REQUEST
                        )
                    }

                    "openNotificationListenerSettings" -> {
                        try {
                            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
                            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            startActivity(intent)
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to open notification listener settings", e)
                            result.error(
                                "SETTINGS_ERROR",
                                "Failed to open notification settings: ${e.message}",
                                null
                            )
                        }
                    }

                    "isNotificationListenerEnabled" -> {
                        try {
                            val enabledListeners = Settings.Secure.getString(
                                contentResolver,
                                "enabled_notification_listeners"
                            ) ?: ""
                            val isEnabled = enabledListeners.contains(packageName)
                            result.success(isEnabled)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to check notification listener status", e)
                            result.success(false)
                        }
                    }

                    "enableFlagSecure" -> {
                        try {
                            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            Log.d(TAG, "FLAG_SECURE enabled — anti-tapjacking active")
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to set FLAG_SECURE", e)
                            result.error("FLAG_SECURE_ERROR", "Failed to set FLAG_SECURE: ${e.message}", null)
                        }
                    }

                    // ── Overlay Control ──────────────────────────────
                    "showLockdownOverlay" -> {
                        try {
                            if (android.provider.Settings.canDrawOverlays(this@MainActivity)) {
                                val intent = android.content.Intent(this@MainActivity, OverlayService::class.java)
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                                    startForegroundService(intent)
                                } else {
                                    startService(intent)
                                }
                                Log.d(TAG, "OverlayService started — lockdown active")
                                result.success(true)
                            } else {
                                Log.w(TAG, "SYSTEM_ALERT_WINDOW permission not granted")
                                result.error("PERMISSION_DENIED", "Overlay permission not granted", null)
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to start OverlayService", e)
                            result.error("OVERLAY_ERROR", "Failed to start overlay: ${e.message}", null)
                        }
                    }

                    "hideLockdownOverlay" -> {
                        try {
                            val intent = android.content.Intent(this@MainActivity, OverlayService::class.java)
                            stopService(intent)
                            Log.d(TAG, "OverlayService stopped — lockdown dismissed")
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to stop OverlayService", e)
                            result.error("OVERLAY_ERROR", "Failed to stop overlay: ${e.message}", null)
                        }
                    }

                    "checkOverlayPermission" -> {
                        val canDraw = android.provider.Settings.canDrawOverlays(this@MainActivity)
                        result.success(canDraw)
                    }

                    "requestOverlayPermission" -> {
                        try {
                            val intent = android.content.Intent(
                                android.provider.Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                android.net.Uri.parse("package:$packageName")
                            )
                            startActivity(intent)
                            result.success(true)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to open overlay settings", e)
                            result.error("SETTINGS_ERROR", "Failed to open settings: ${e.message}", null)
                        }
                    }

                    else -> result.notImplemented()
                }
            }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, ACCESSIBILITY_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "checkRogueAccessibility" -> {
                        try {
                            result.success(checkRogueAccessibility())
                        } catch (e: Exception) {
                            Log.e(TAG, "Accessibility hijack scan failed", e)
                            result.error(
                                "ACCESSIBILITY_SCAN_ERROR",
                                "Accessibility scan failed: ${e.message}",
                                null
                            )
                        }
                    }

                    else -> result.notImplemented()
                }
            }

        // ── Notification Snooper Detection Channel ──
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, NOTIFICATION_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "checkRogueNotificationListeners" -> {
                        try {
                            result.success(checkRogueNotificationListeners())
                        } catch (e: Exception) {
                            Log.e(TAG, "Notification listener scan failed", e)
                            result.error(
                                "NOTIFICATION_SCAN_ERROR",
                                "Notification listener scan failed: ${e.message}",
                                null
                            )
                        }
                    }

                    else -> result.notImplemented()
                }
            }

        // ── Hardware Attestation Channel (Play Integrity API) ──
        // Requests a cryptographic integrity token from the device's TEE
        // (Trusted Execution Environment) via Google Play Services.
        //
        // ⚠️ PRODUCTION NOTE:
        //   In a production deployment, the raw integrity token (JWS) should
        //   be sent to the KAVACH Python backend for server-side decryption:
        //     POST https://playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken
        //   Client-side JWT parsing (this MVP) is NOT production-safe —
        //   an attacker with root access can intercept the MethodChannel.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, INTEGRITY_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "requestIntegrityVerdict" -> {
                        CoroutineScope(Dispatchers.Main).launch {
                            try {
                                val verdict = requestIntegrityVerdict()
                                result.success(verdict)
                            } catch (e: Exception) {
                                Log.e(TAG, "Play Integrity attestation failed", e)
                                result.error(
                                    "INTEGRITY_ERROR",
                                    "Hardware attestation failed: ${e.message}",
                                    null
                                )
                            }
                        }
                    }

                    else -> result.notImplemented()
                }
            }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    Log.d(TAG, "Flutter started listening for SMS events")
                    SmsReceiver.eventSink = events
                }

                override fun onCancel(arguments: Any?) {
                    Log.d(TAG, "Flutter stopped listening for SMS events")
                    SmsReceiver.eventSink = null
                }
            })
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        when (requestCode) {
            SMS_PERMISSION_REQUEST -> {
                val granted =
                    grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
                pendingSmsPermissionResult?.success(granted)
                pendingSmsPermissionResult = null
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == OVERLAY_PERMISSION_REQUEST) {
            Log.d(TAG, "Overlay permission result: ${Settings.canDrawOverlays(this)}")
        }
    }

    private fun extractVerdict(securityResult: Any): String {
        return when (securityResult) {
            is String -> securityResult
            is Map<*, *> -> securityResult["verdict"] as? String ?: "UNKNOWN"
            else -> "UNKNOWN"
        }
    }

    private fun checkRogueAccessibility(): Map<String, Any?> {
        val accessibilityManager =
            getSystemService(ACCESSIBILITY_SERVICE) as? AccessibilityManager

        if (accessibilityManager == null) {
            Log.w(TAG, "AccessibilityManager unavailable; returning safe result")
            return mapOf(
                "isThreat" to false,
                "rogueServices" to emptyList<Map<String, Any?>>(),
                "packageName" to null,
                "appName" to null
            )
        }

        val enabledServices = accessibilityManager.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        )

        Log.d(TAG, "Accessibility scan: ${enabledServices.size} enabled service(s)")

        val rogueServices = mutableListOf<Map<String, Any?>>()

        for (serviceInfo in enabledServices) {
            val resolveInfo = serviceInfo.resolveInfo ?: continue
            val serviceMeta = resolveInfo.serviceInfo ?: continue
            val pkgName = serviceMeta.packageName ?: continue

            // ── Installer Verification ──
            val installer = getInstallerForPackage(pkgName)
            val isTrusted = installer != null && TRUSTED_INSTALLERS.contains(installer)

            if (isTrusted) {
                Log.d(TAG, "Accessibility SAFE (store-installed): $pkgName [installer=$installer]")
                continue
            }

            // Sideloaded app with active Accessibility Service → THREAT
            val applicationInfo = serviceMeta.applicationInfo
            val appName = try {
                packageManager.getApplicationLabel(applicationInfo).toString().ifBlank {
                    pkgName
                }
            } catch (_: Exception) {
                pkgName
            }
            val serviceLabel = try {
                resolveInfo.loadLabel(packageManager).toString()
            } catch (_: Exception) {
                pkgName
            }

            Log.w(
                TAG,
                "ROGUE ACCESSIBILITY SERVICE (sideloaded): $pkgName " +
                    "[installer=${installer ?: "null"}, service=$serviceLabel]"
            )

            rogueServices.add(
                mapOf(
                    "packageName" to pkgName,
                    "appName" to appName,
                    "serviceName" to serviceLabel,
                    "installer" to (installer ?: "UNKNOWN")
                )
            )
        }

        if (rogueServices.isNotEmpty()) {
            // Return the first rogue service as the primary threat
            // and attach the full list for telemetry logging.
            val primary = rogueServices.first()
            return mapOf(
                "isThreat" to true,
                "packageName" to primary["packageName"],
                "appName" to primary["appName"],
                "serviceName" to primary["serviceName"],
                "installer" to primary["installer"],
                "rogueServices" to rogueServices
            )
        }

        return mapOf(
            "isThreat" to false,
            "rogueServices" to emptyList<Map<String, Any?>>(),
            "packageName" to null,
            "appName" to null
        )
    }

    /**
     * Detect sideloaded apps that have been granted notification listener access.
     * Uses the same Installer Verification logic as the accessibility scanner.
     *
     * Reads `enabled_notification_listeners` from Settings.Secure, parses the
     * component names to extract package names, then checks each one's installer.
     * Sideloaded apps (null / unknown installer) are flagged as threats.
     *
     * Gracefully handles null or empty settings strings.
     */
    private fun checkRogueNotificationListeners(): Map<String, Any?> {
        val enabledListenersRaw: String? = try {
            Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read enabled_notification_listeners", e)
            null
        }

        if (enabledListenersRaw.isNullOrBlank()) {
            Log.d(TAG, "No notification listeners enabled")
            return mapOf(
                "isThreat" to false,
                "rogueListeners" to emptyList<Map<String, Any?>>(),
                "packageName" to null,
                "appName" to null
            )
        }

        // The string is a colon-delimited list of ComponentName flattened strings:
        // e.g. "com.example.app/.MyService:com.other.app/.Listener"
        val componentNames = enabledListenersRaw.split(":")
            .map { it.trim() }
            .filter { it.isNotEmpty() }

        // Extract unique package names (before the "/")
        val activePackages = componentNames
            .mapNotNull { cn ->
                val slashIndex = cn.indexOf("/")
                if (slashIndex > 0) cn.substring(0, slashIndex) else cn.split("/").firstOrNull()
            }
            .distinct()

        Log.d(TAG, "Notification listener scan: ${activePackages.size} active package(s)")

        val rogueListeners = mutableListOf<Map<String, Any?>>()

        for (pkgName in activePackages) {
            // Skip our own package
            if (pkgName == packageName) continue

            val installer = getInstallerForPackage(pkgName)
            val isTrusted = installer != null && TRUSTED_INSTALLERS.contains(installer)

            if (isTrusted) {
                Log.d(TAG, "Notification listener SAFE (store-installed): $pkgName [installer=$installer]")
                continue
            }

            // Sideloaded app with active notification listener → THREAT
            val appName = try {
                val appInfo = packageManager.getApplicationInfo(pkgName, 0)
                packageManager.getApplicationLabel(appInfo).toString().ifBlank { pkgName }
            } catch (_: Exception) {
                pkgName
            }

            Log.w(
                TAG,
                "ROGUE NOTIFICATION LISTENER (sideloaded): $pkgName " +
                    "[installer=${installer ?: "null"}]"
            )

            rogueListeners.add(
                mapOf(
                    "packageName" to pkgName,
                    "appName" to appName,
                    "installer" to (installer ?: "UNKNOWN")
                )
            )
        }

        if (rogueListeners.isNotEmpty()) {
            val primary = rogueListeners.first()
            return mapOf(
                "isThreat" to true,
                "packageName" to primary["packageName"],
                "appName" to primary["appName"],
                "installer" to primary["installer"],
                "rogueListeners" to rogueListeners
            )
        }

        return mapOf(
            "isThreat" to false,
            "rogueListeners" to emptyList<Map<String, Any?>>(),
            "packageName" to null,
            "appName" to null
        )
    }

    /**
     * Returns the installer package name for [pkgName], handling the
     * API 30+ (InstallSourceInfo) vs legacy (getInstallerPackageName) split.
     * Returns null if the installer cannot be determined (= sideloaded APK).
     */
    @Suppress("DEPRECATION")
    private fun getInstallerForPackage(pkgName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val sourceInfo: InstallSourceInfo =
                    packageManager.getInstallSourceInfo(pkgName)
                // installingPackageName is the store that performed the install.
                sourceInfo.installingPackageName
            } else {
                packageManager.getInstallerPackageName(pkgName)
            }
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(TAG, "getInstallerForPackage: $pkgName not found", e)
            null
        } catch (e: Exception) {
            Log.w(TAG, "getInstallerForPackage: $pkgName failed", e)
            null
        }
    }

    // =========================================================================
    // PLAY INTEGRITY API — Hardware TEE Attestation
    // =========================================================================
    //
    // Requests an integrity token from Google Play Services, which leverages
    // the device's Trusted Execution Environment (hardware security module)
    // to produce a signed attestation that CANNOT be spoofed by software
    // rootkits like Magisk.
    //
    // The token is a JWS (JSON Web Signature) with three base64url-encoded
    // parts: header.payload.signature.  The payload contains device verdict
    // labels that indicate the device's integrity state.
    //
    // Verdict Labels:
    //   MEETS_STRONG_INTEGRITY  — Hardware-backed keystore, verified boot
    //   MEETS_DEVICE_INTEGRITY  — Genuine Android, locked bootloader
    //   MEETS_BASIC_INTEGRITY   — Basic checks pass (may have unlocked BL)
    //   (empty)                 — Rooted, emulator, or custom ROM
    //
    // ⚠️ PRODUCTION: The raw token must be sent server-side for proper
    //    cryptographic verification. Client-side JWT decode is MVP-only.
    // =========================================================================

    /**
     * Generate a cryptographic nonce for the integrity request.
     *
     * The nonce prevents replay attacks — each attestation request must
     * include a unique, unpredictable value. In production, this nonce
     * should be generated server-side and validated on token verification.
     */
    private fun generateNonce(): String {
        val timestamp = System.currentTimeMillis()
        val raw = "$packageName:$timestamp:${System.nanoTime()}"
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray())
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    /**
     * Request an integrity verdict from the device's TEE via Play Integrity API.
     *
     * Flow:
     *   1. Generate a cryptographic nonce (anti-replay)
     *   2. Create IntegrityManager from IntegrityManagerFactory
     *   3. Build IntegrityTokenRequest with nonce + cloud project number
     *   4. Request token from TEE (async, awaits Google Play Services)
     *   5. Parse the JWS payload to extract device verdict labels
     *   6. Return a map of boolean flags for Flutter consumption
     *
     * @return Map with keys: meetsDeviceIntegrity, meetsBasicIntegrity,
     *         meetsStrongIntegrity, verdictLabels, rawToken
     */
    private suspend fun requestIntegrityVerdict(): Map<String, Any> {
        val nonce = generateNonce()
        Log.d(TAG, "Play Integrity: requesting token with nonce=${nonce.take(16)}...")

        // ── Create Integrity Manager ──
        val integrityManager = IntegrityManagerFactory.create(applicationContext)

        // ── Build Token Request ──
        val requestBuilder = IntegrityTokenRequest.builder()
            .setNonce(nonce)

        // Only set cloud project number if configured (non-zero)
        if (CLOUD_PROJECT_NUMBER != 0L) {
            requestBuilder.setCloudProjectNumber(CLOUD_PROJECT_NUMBER)
        }

        val tokenRequest = requestBuilder.build()

        // ── Request Token from TEE ──
        // This call goes to Google Play Services, which communicates with
        // the device's Trusted Execution Environment to produce a signed
        // attestation token.  Requires network connectivity to Google servers.
        val tokenResponse = integrityManager.requestIntegrityToken(tokenRequest).await()
        val token = tokenResponse.token()

        Log.d(TAG, "Play Integrity: received token (${token.length} chars)")

        // ── Parse JWT Payload (MVP: Client-Side) ──
        // The token is a JWS: base64url(header).base64url(payload).base64url(signature)
        //
        // ⚠️ PRODUCTION WARNING:
        //   This client-side decode does NOT verify the signature.
        //   In production, send `token` to your backend which calls:
        //     POST playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken
        //   with your service account credentials.  The backend then returns
        //   the verified verdict to the client.
        val verdictLabels = parseVerdictLabelsFromToken(token)

        val meetsBasic = verdictLabels.contains("MEETS_BASIC_INTEGRITY")
        val meetsDevice = verdictLabels.contains("MEETS_DEVICE_INTEGRITY")
        val meetsStrong = verdictLabels.contains("MEETS_STRONG_INTEGRITY")

        Log.i(
            TAG,
            "Play Integrity verdict: basic=$meetsBasic, device=$meetsDevice, " +
                "strong=$meetsStrong, labels=$verdictLabels"
        )

        return mapOf(
            "meetsBasicIntegrity" to meetsBasic,
            "meetsDeviceIntegrity" to meetsDevice,
            "meetsStrongIntegrity" to meetsStrong,
            "verdictLabels" to verdictLabels,
            "rawToken" to token  // For server-side verification in production
        )
    }

    /**
     * Extract device verdict labels from the JWS token payload.
     *
     * The JWS payload (second dot-delimited segment) is a base64url-encoded
     * JSON object with the structure:
     *   {
     *     "deviceIntegrity": {
     *       "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY", ...]
     *     },
     *     ...
     *   }
     *
     * ⚠️ MVP ONLY — does not verify the JWS signature.
     */
    private fun parseVerdictLabelsFromToken(token: String): List<String> {
        return try {
            val parts = token.split(".")
            if (parts.size != 3) {
                Log.w(TAG, "Integrity token has ${parts.size} parts (expected 3)")
                return emptyList()
            }

            val payloadBytes = Base64.decode(parts[1], Base64.URL_SAFE)
            val payload = JSONObject(String(payloadBytes, Charsets.UTF_8))

            val deviceIntegrity = payload.optJSONObject("deviceIntegrity")
            val verdictArray = deviceIntegrity?.optJSONArray("deviceRecognitionVerdict")

            if (verdictArray == null) {
                Log.w(TAG, "No deviceRecognitionVerdict in integrity payload")
                return emptyList()
            }

            val labels = mutableListOf<String>()
            for (i in 0 until verdictArray.length()) {
                labels.add(verdictArray.getString(i))
            }
            labels
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse integrity token payload", e)
            emptyList()
        }
    }
}
