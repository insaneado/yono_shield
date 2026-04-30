package com.example.yono_shield

// =============================================================================
// YONO SHIELD — OmniScannerService.kt
// =============================================================================
// Universal NotificationListenerService that intercepts incoming messages
// across ALL delivery channels (SMS, WhatsApp, Telegram, Signal, etc.),
// extracts URLs, sends them to the KAVACH Python backend for heuristic
// scanning, and fires a high-priority heads-up alert if a phishing threat
// is detected.
//
// Pipeline:
//   Notification posted
//     → Extract text (EXTRA_TEXT / EXTRA_BIG_TEXT)
//     → Contains URL?  → POST to KAVACH backend
//     → Response "BLOCKED"?  → Fire heads-up alert notification
//                             → Launch Flutter Red Alert via PendingIntent
//
// Network I/O runs on Dispatchers.IO via Kotlin Coroutines.
// If the backend is offline the service fails silently — no crash.
// =============================================================================

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class OmniScannerService : NotificationListenerService() {

    companion object {
        private const val TAG = "YonoShield:OmniScan"

        // ── Notification channel for phishing alerts ──
        private const val CHANNEL_ID = "yono_shield_omni_alerts"
        private const val CHANNEL_NAME = "KAVACH Phishing Alerts"
        private const val CHANNEL_DESC =
            "High-priority alerts when a phishing link is detected in any messaging app."

        // ── KAVACH backend endpoint ──
        private const val KAVACH_ENDPOINT = "https://filth-endurable-swear.ngrok-free.dev/webhook/whatsapp"
        private const val DEVICE_USER_ID = "device_1"

        // ── Simple URL detection pattern ──
        private val URL_PATTERN = Regex("https?://\\S+", RegexOption.IGNORE_CASE)

        // ── Notification IDs ──
        private const val ALERT_NOTIFICATION_BASE_ID = 7000
    }

    // Coroutine scope tied to the service lifecycle.
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // =========================================================================
    // onListenerConnected / onListenerDisconnected — lifecycle logging
    // =========================================================================

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.d(TAG, "✅ OmniScannerService connected — monitoring ALL notifications")
        ensureNotificationChannel()
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        Log.w(TAG, "⚠️ OmniScannerService disconnected")
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
        Log.d(TAG, "OmniScannerService destroyed — coroutine scope cancelled")
    }

    // =========================================================================
    // onNotificationPosted — the core interception point
    // =========================================================================

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return

        // Ignore our own notifications to avoid infinite loops.
        if (sbn.packageName == packageName) return

        // ── Extract notification text ──
        val extras = sbn.notification.extras
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""

        // Prefer the most detailed text available.
        val messageContent = when {
            !bigText.isNullOrBlank() -> bigText
            !text.isNullOrBlank() -> text
            else -> return  // No text content — nothing to scan.
        }

        // ── Check for URLs in the notification text ──
        if (!URL_PATTERN.containsMatchIn(messageContent)) {
            return  // No URLs — nothing to do.
        }

        Log.d(
            TAG,
            "🔗 URL detected in notification from ${sbn.packageName}: " +
                "${messageContent.take(80)}…"
        )

        // ── Fire backend scan on a background coroutine ──
        serviceScope.launch {
            scanWithKavachBackend(
                messageText = messageContent,
                sourceApp = sbn.packageName,
                senderTitle = title
            )
        }
    }

    // =========================================================================
    // Network: POST to KAVACH backend (runs on Dispatchers.IO)
    // =========================================================================

    private suspend fun scanWithKavachBackend(
        messageText: String,
        sourceApp: String,
        senderTitle: String
    ) {
        try {
            val payload = JSONObject().apply {
                put("user_id", DEVICE_USER_ID)
                put("message_text", messageText)
            }

            val connection = (URL(KAVACH_ENDPOINT).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 5_000
                readTimeout = 5_000
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=UTF-8")
                setRequestProperty("Accept", "application/json")
            }

            // Write the JSON payload.
            connection.outputStream.use { os ->
                OutputStreamWriter(os, Charsets.UTF_8).use { writer ->
                    writer.write(payload.toString())
                    writer.flush()
                }
            }

            val responseCode = connection.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "KAVACH backend returned HTTP $responseCode")
                connection.disconnect()
                return
            }

            val responseBody = connection.inputStream.bufferedReader().use { it.readText() }
            connection.disconnect()

            val response = JSONObject(responseBody)
            val status = response.optString("status", "SAFE")

            Log.d(TAG, "KAVACH verdict: $status for message from $sourceApp")

            if (status == "BLOCKED") {
                val alertText = response.optString(
                    "alert",
                    "Phishing link detected. Do not click."
                )
                Log.w(TAG, "🚨 PHISHING BLOCKED from $sourceApp: $alertText")

                // Fire heads-up notification on the main thread.
                withContext(Dispatchers.Main) {
                    fireThreatNotification(
                        sourceApp = sourceApp,
                        senderTitle = senderTitle,
                        alertText = alertText,
                        messageText = messageText
                    )
                }
            }

        } catch (e: Exception) {
            // Fail silently — the backend may be offline during demo.
            // The user experience must never be degraded by backend outages.
            Log.w(TAG, "KAVACH backend unreachable: ${e.javaClass.simpleName} — ${e.message}")
        }
    }

    // =========================================================================
    // Notification: Fire a heads-up phishing alert
    // =========================================================================

    private fun fireThreatNotification(
        sourceApp: String,
        senderTitle: String,
        alertText: String,
        messageText: String
    ) {
        ensureNotificationChannel()

        // Check POST_NOTIFICATIONS permission on Android 13+.
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.w(TAG, "POST_NOTIFICATIONS not granted — cannot show alert")
            return
        }

        // ── PendingIntent: tap to open YONO Shield (Flutter Red Alert) ──
        val reviewIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("threat_source", "OMNI_SCAN")
            putExtra("threat_source_app", sourceApp)
            putExtra("threat_message", messageText)
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            (sourceApp + messageText).hashCode(),
            reviewIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val displaySource = senderTitle.ifBlank { sourceApp }
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("\uD83D\uDEA8 KAVACH: Phishing Link Blocked")
            .setContentText("Threat from: $displaySource")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .setBigContentTitle("\uD83D\uDEA8 KAVACH: Phishing Link Blocked")
                    .setSummaryText("Source: $displaySource")
                    .bigText(alertText)
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val notifId = ALERT_NOTIFICATION_BASE_ID + (sourceApp + messageText).hashCode() % 1000
        NotificationManagerCompat.from(this).notify(notifId, notification)
    }

    // =========================================================================
    // Notification Channel Setup
    // =========================================================================

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = CHANNEL_DESC
            enableLights(true)
            enableVibration(true)
            lockscreenVisibility = NotificationCompat.VISIBILITY_PUBLIC
        }

        manager.createNotificationChannel(channel)
        Log.d(TAG, "Notification channel '$CHANNEL_ID' created")
    }
}
