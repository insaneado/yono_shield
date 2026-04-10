package com.example.yono_shield

// ============================================================================
// YONO SHIELD — SmsReceiver.kt
// ============================================================================
// PILLAR 2: SMS Interceptor (BroadcastReceiver approach)
//
// This BroadcastReceiver listens for incoming SMS messages via the
// android.provider.Telephony.SMS_RECEIVED action. When an SMS arrives,
// it extracts the message body, checks if it contains a URL, and if so,
// forwards the entire message text to Flutter via a static EventChannel sink.
//
// The URL detection is intentionally broad to catch obfuscated phishing links
// (e.g., "bit.ly/xyz", "tinyurl.com/abc", raw IP addresses, etc.).
//
// IMPORTANT: This receiver is registered in AndroidManifest.xml with high
// priority (999) to intercept messages before the default SMS app.
// ============================================================================

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import io.flutter.plugin.common.EventChannel

class SmsReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "YonoShield:SmsReceiver"

        // ====================================================================
        // Static EventSink reference
        // This is set by MainActivity when the EventChannel is initialized.
        // When an SMS arrives, we push it through this sink to Flutter.
        // ====================================================================
        var eventSink: EventChannel.EventSink? = null

        // ====================================================================
        // URL_REGEX — Broad pattern to catch various URL formats:
        //   - Standard HTTP/HTTPS URLs
        //   - Short URLs (bit.ly, tinyurl.com, etc.)
        //   - URLs without protocol (www.example.com)
        //   - IP-based URLs (http://192.168.1.1/phish)
        // ====================================================================
        val URL_REGEX = Regex(
            """(https?://[^\s]+)""" +                    // Standard URLs
            """|(www\.[^\s]+)""" +                        // www. prefixed
            """|([a-zA-Z0-9-]+\.(ly|io|co|me|cc|tk|ml|ga|cf|gq|top|xyz|click|link|info|live|online|site|fun|icu|buzz|shop)/[^\s]*)""" + // Short URL domains
            """|(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s]*)""", // IP-based URLs
            RegexOption.IGNORE_CASE
        )
    }

    // ========================================================================
    // onReceive()
    //
    // Called by the Android system when an SMS_RECEIVED broadcast is fired.
    // Extracts message body from the SMS PDU and forwards to Flutter if
    // a URL is detected.
    // ========================================================================
    override fun onReceive(context: Context?, intent: Intent?) {
        if (intent?.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        Log.d(TAG, "SMS_RECEIVED broadcast intercepted")

        // Extract SMS messages from the intent
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)

        if (messages.isNullOrEmpty()) {
            Log.w(TAG, "No messages found in SMS intent")
            return
        }

        // Concatenate all message parts (multi-part SMS)
        val fullMessage = StringBuilder()
        var senderAddress = ""

        for (smsMessage in messages) {
            fullMessage.append(smsMessage.messageBody)
            senderAddress = smsMessage.originatingAddress ?: "Unknown"
        }

        val messageText = fullMessage.toString()
        Log.d(TAG, "SMS from $senderAddress: ${messageText.take(50)}...")

        // Check if the message contains a URL
        val containsUrl = URL_REGEX.containsMatchIn(messageText)

        if (containsUrl) {
            Log.w(TAG, "⚠️ URL detected in SMS from $senderAddress — forwarding to Flutter")

            // Build the payload to send to Flutter
            // Format: "SENDER||MESSAGE_BODY" so Flutter can parse both parts
            val payload = "$senderAddress||$messageText"

            // Push to Flutter via the static EventSink
            try {
                eventSink?.success(payload)
                    ?: Log.w(TAG, "EventSink is null — Flutter not listening yet")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to push SMS to Flutter EventSink", e)
            }
        } else {
            Log.d(TAG, "SMS does not contain URL — ignoring")
        }
    }
}
