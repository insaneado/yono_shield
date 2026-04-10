package com.example.yono_shield

// ============================================================================
// YONO SHIELD — OverlayService.kt
// ============================================================================
// PILLAR 3: Block Overlay
//
// This foreground service uses the SYSTEM_ALERT_WINDOW permission to draw a
// full-screen blocking overlay on top of all other apps. When a malicious
// app is detected, this overlay prevents the user from interacting with it.
//
// The overlay displays:
//   - A red warning background
//   - "⚠️ MALICIOUS APP DETECTED" heading
//   - "YONO SHIELD ACTIVE" subheading
//   - A "Dismiss & Return to Safety" button
//
// The service runs as a foreground service with a persistent notification
// to comply with Android's background service restrictions.
// ============================================================================

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.IBinder
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.app.NotificationCompat

class OverlayService : Service() {

    companion object {
        private const val TAG = "YonoShield:Overlay"
        private const val NOTIFICATION_CHANNEL_ID = "yono_shield_protection"
        private const val NOTIFICATION_ID = 1001
    }

    // Reference to the overlay view so we can remove it later
    private var overlayView: View? = null
    private var windowManager: WindowManager? = null

    // ========================================================================
    // onBind() — Not a bound service, return null
    // ========================================================================
    override fun onBind(intent: Intent?): IBinder? = null

    // ========================================================================
    // onCreate() — Initialize the foreground notification channel
    // ========================================================================
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "OverlayService created")
        createNotificationChannel()
    }

    // ========================================================================
    // onStartCommand() — Show the blocking overlay
    // ========================================================================
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "OverlayService started — drawing blocking overlay")

        // Start as foreground service with a notification
        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("🛡️ YONO Shield Active")
            .setContentText("Blocking a potentially malicious application")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setOngoing(true)
            .build()

        startForeground(NOTIFICATION_ID, notification)

        // Draw the overlay
        showOverlay()

        return START_NOT_STICKY
    }

    // ========================================================================
    // showOverlay()
    //
    // Creates a full-screen overlay view with a red gradient background,
    // warning text, and a dismiss button. Uses WindowManager to draw
    // on top of all other apps.
    // ========================================================================
    private fun showOverlay() {
        // Don't create duplicate overlays
        if (overlayView != null) {
            Log.w(TAG, "Overlay already showing — skipping")
            return
        }

        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager

        // ====================================================================
        // BUILD THE OVERLAY LAYOUT
        // ====================================================================
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(64, 64, 64, 64)

            // Dark red gradient background
            background = GradientDrawable(
                GradientDrawable.Orientation.TOP_BOTTOM,
                intArrayOf(
                    Color.parseColor("#1A0000"),  // Very dark red/black at top
                    Color.parseColor("#8B0000"),  // Dark red in middle
                    Color.parseColor("#CC0000")   // Bright red at bottom
                )
            )
        }

        // ⚠️ Warning Icon (large text emoji)
        val iconText = TextView(this).apply {
            text = "⚠️"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 80f)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 32)
        }

        // 🛡️ Shield icon
        val shieldText = TextView(this).apply {
            text = "🛡️"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 60f)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 48)
        }

        // Main warning heading
        val headingText = TextView(this).apply {
            text = "MALICIOUS APP\nDETECTED"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 36f)
            setTextColor(Color.WHITE)
            typeface = Typeface.create("sans-serif-black", Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 24)
            letterSpacing = 0.1f
        }

        // Sub-heading
        val subText = TextView(this).apply {
            text = "YONO SHIELD IS PROTECTING YOUR DEVICE"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTextColor(Color.parseColor("#FFCCCC"))
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 16)
            letterSpacing = 0.15f
        }

        // Description
        val descText = TextView(this).apply {
            text = "A potentially dangerous application has been detected.\n" +
                   "This overlay is blocking access to protect your data\n" +
                   "and financial information."
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setTextColor(Color.parseColor("#FF9999"))
            gravity = Gravity.CENTER
            setPadding(32, 0, 32, 64)
            setLineSpacing(8f, 1f)
        }

        // Dismiss button
        val dismissButton = Button(this).apply {
            text = "✕  DISMISS & RETURN TO SAFETY"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTextColor(Color.parseColor("#CC0000"))
            typeface = Typeface.create("sans-serif-bold", Typeface.BOLD)
            letterSpacing = 0.05f
            setPadding(48, 32, 48, 32)

            // White rounded button background
            background = GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = 100f // Pill shape
            }

            setOnClickListener {
                Log.d(TAG, "Dismiss button pressed — removing overlay")
                dismissOverlay()
            }
        }

        // Assemble the layout
        layout.addView(iconText)
        layout.addView(shieldText)
        layout.addView(headingText)
        layout.addView(subText)
        layout.addView(descText)
        layout.addView(dismissButton)

        // ====================================================================
        // WINDOW PARAMS — Full-screen overlay on top of everything
        // ====================================================================
        val overlayType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
        }

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            overlayType,
            // FLAG_NOT_FOCUSABLE is NOT set — we want the dismiss button to be clickable
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        )
        params.gravity = Gravity.CENTER

        // Add the overlay to the window
        overlayView = layout
        windowManager?.addView(overlayView, params)

        Log.d(TAG, "Blocking overlay is now visible")
    }

    // ========================================================================
    // dismissOverlay() — Remove the overlay and stop the service
    // ========================================================================
    private fun dismissOverlay() {
        try {
            overlayView?.let {
                windowManager?.removeView(it)
                overlayView = null
                Log.d(TAG, "Overlay view removed")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error removing overlay view", e)
        }

        // Stop the foreground service
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.d(TAG, "OverlayService stopped")
    }

    // ========================================================================
    // onDestroy() — Cleanup: ensure overlay is removed
    // ========================================================================
    override fun onDestroy() {
        super.onDestroy()
        dismissOverlay()
        Log.d(TAG, "OverlayService destroyed — cleanup complete")
    }

    // ========================================================================
    // createNotificationChannel() — Required for Android 8.0+ foreground services
    // ========================================================================
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "YONO Shield Protection",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Active threat protection notifications"
                enableLights(true)
                lightColor = Color.RED
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
            Log.d(TAG, "Notification channel created: $NOTIFICATION_CHANNEL_ID")
        }
    }
}
