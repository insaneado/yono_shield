package com.example.yono_shield

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

class AppInstallReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "YonoShield:InstallRx"
        private const val ALERT_CHANNEL_ID = "yono_shield_install_alerts"
        private const val ALERT_CHANNEL_NAME = "YONO Shield Threat Alerts"
        private const val ALERT_CHANNEL_DESCRIPTION =
            "High-priority alerts for malicious apps detected after installation."
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_PACKAGE_ADDED) {
            return
        }

        if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
            Log.d(TAG, "Ignoring package update broadcast")
            return
        }

        val newPackageName = intent.data?.encodedSchemeSpecificPart
        if (newPackageName.isNullOrBlank()) {
            Log.w(TAG, "Package install broadcast missing package name")
            return
        }

        if (newPackageName == context.packageName) {
            Log.d(TAG, "Ignoring YONO Shield package install event")
            return
        }

        val securityManager = SecurityManager(context.applicationContext)
        val securityResult = securityManager.verifyAppSecurity(newPackageName)
        val verdict = extractVerdict(securityResult)

        Log.d(TAG, "Install monitor verdict for $newPackageName: $verdict")

        if (verdict.startsWith("TROJAN_DETECTED_") || verdict == "INVALID_SIGNATURE") {
            showThreatNotification(context, verdict, newPackageName)
        }
    }

    private fun extractVerdict(result: Any): String {
        return when (result) {
            is String -> result
            is Map<*, *> -> result["verdict"] as? String ?: "UNKNOWN"
            else -> "UNKNOWN"
        }
    }

    private fun showThreatNotification(context: Context, verdict: String, packageName: String) {
        createThreatChannel(context)

        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.w(TAG, "POST_NOTIFICATIONS not granted; cannot show threat alert")
            return
        }

        val reviewIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("threat_verdict", verdict)
            putExtra("threat_package_name", packageName)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            packageName.hashCode(),
            reviewIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("\uD83D\uDEA8 YONO SHIELD ALERT")
            .setContentText("Malicious app detected and blocked. Tap to review.")
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    "Malicious app detected and blocked. Tap to review."
                )
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        NotificationManagerCompat.from(context).notify(packageName.hashCode(), notification)
    }

    private fun createThreatChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val existingChannel = manager.getNotificationChannel(ALERT_CHANNEL_ID)
        if (existingChannel != null) {
            return
        }

        val channel = NotificationChannel(
            ALERT_CHANNEL_ID,
            ALERT_CHANNEL_NAME,
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = ALERT_CHANNEL_DESCRIPTION
            enableLights(true)
            enableVibration(true)
            lockscreenVisibility = NotificationCompat.VISIBILITY_PUBLIC
        }

        manager.createNotificationChannel(channel)
    }
}
