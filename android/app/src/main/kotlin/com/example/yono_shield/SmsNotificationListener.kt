package com.example.yono_shield

// ============================================================================
// YONO SHIELD — SmsNotificationListener.kt
// ============================================================================
// PILLAR 2 (Fallback): Notification Listener SMS Interceptor
//
// This is a NotificationListenerService that acts as a fallback when the
// BroadcastReceiver cannot intercept SMS (e.g., on Android 14+ where
// RECEIVE_SMS is restricted to the default SMS app).
//
// It monitors all incoming notifications and filters for messaging apps
// (SMS, WhatsApp, etc.). When a notification containing a URL is detected,
// the message text is forwarded to Flutter via the same EventChannel sink
// used by SmsReceiver.
//
// SETUP REQUIRED: The user must manually enable this service in
// Settings > Apps > Special Access > Notification Access > YONO Shield
// ============================================================================

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log

class SmsNotificationListener : NotificationListenerService() {

    companion object {
        private const val TAG = "YonoShield:NotifListener"

        // Package names of messaging apps to monitor for phishing links
        val MESSAGING_PACKAGES = setOf(
            "com.google.android.apps.messaging",  // Google Messages
            "com.samsung.android.messaging",       // Samsung Messages
            "com.android.mms",                     // Default Android MMS
            "com.whatsapp",                        // WhatsApp
            "org.telegram.messenger",              // Telegram
            "com.facebook.orca"                    // Facebook Messenger
        )
    }

    // ========================================================================
    // onNotificationPosted()
    //
    // Called by the Android system whenever a new notification is posted.
    // We filter for messaging app notifications, extract the text content,
    // check for URLs, and forward to Flutter if a link is detected.
    // ========================================================================
    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return

        val packageName = sbn.packageName

        // Only monitor notifications from messaging apps
        if (!MESSAGING_PACKAGES.contains(packageName)) return

        Log.d(TAG, "Notification from messaging app: $packageName")

        // Extract notification text content
        val extras = sbn.notification.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""

        // Use the most detailed text available
        val messageContent = when {
            bigText.isNotEmpty() -> bigText
            text.isNotEmpty() -> text
            else -> return // No text content to analyze
        }

        Log.d(TAG, "Notification text: ${messageContent.take(50)}...")

        // Check if the message contains a URL using the same regex as SmsReceiver
        val containsUrl = SmsReceiver.URL_REGEX.containsMatchIn(messageContent)

        if (containsUrl) {
            Log.w(TAG, "⚠️ URL detected in notification from $packageName — forwarding to Flutter")

            // Build the payload in the same format as SmsReceiver
            // "SENDER||MESSAGE_BODY"
            val sender = title.ifEmpty { packageName }
            val payload = "$sender||$messageContent"

            // Push to Flutter via the shared EventSink
            try {
                SmsReceiver.eventSink?.success(payload)
                    ?: Log.w(TAG, "EventSink is null — Flutter not listening yet")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to push notification SMS to Flutter EventSink", e)
            }
        } else {
            Log.d(TAG, "Notification does not contain URL — ignoring")
        }
    }

    // ========================================================================
    // onNotificationRemoved() — Required override, no-op
    // ========================================================================
    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        // Not needed for our use case
    }

    // ========================================================================
    // onListenerConnected() — Service is active and listening
    // ========================================================================
    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.d(TAG, "NotificationListenerService connected — monitoring messaging notifications")
    }

    // ========================================================================
    // onListenerDisconnected() — Service was disconnected
    // ========================================================================
    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        Log.w(TAG, "NotificationListenerService disconnected")
    }
}
