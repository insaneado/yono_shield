package com.example.yono_shield

import android.Manifest
import android.content.Intent
import android.content.pm.ApplicationInfo
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

class MainActivity : FlutterActivity() {

    companion object {
        private const val TAG = "YonoShield:Main"
        private const val METHOD_CHANNEL = "com.yonoshield.security/bridge"
        private const val EVENT_CHANNEL = "com.yonoshield.security/sms_stream"
        private const val SMS_PERMISSION_REQUEST = 2001
        private const val OVERLAY_PERMISSION_REQUEST = 2002
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
}
