// ============================================================================
// YONO SHIELD — Omni-Channel Shield Page
// ============================================================================
// Replaces the placeholder SMS Interceptor. Provides user consent flow
// for Android's NotificationListenerService and real-time status monitoring.
//
// The OmniScannerService (Kotlin) intercepts ALL incoming notifications,
// extracts URLs, and scans them against the KAVACH Python backend.
// This page lets the user enable/disable that protection.
// ============================================================================

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

class SmsPage extends StatefulWidget {
  const SmsPage({super.key});

  @override
  State<SmsPage> createState() => _SmsPageState();
}

class _SmsPageState extends State<SmsPage>
    with SingleTickerProviderStateMixin, WidgetsBindingObserver {
  static const _channel = MethodChannel('com.yonoshield.security/bridge');

  bool _isEnabled = false;
  bool _isChecking = true;
  late AnimationController _pulseCtrl;
  late Animation<double> _pulse;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _pulseCtrl = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    )..repeat(reverse: true);
    _pulse = Tween<double>(begin: 0.4, end: 1.0).animate(
      CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut),
    );
    _checkStatus();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _pulseCtrl.dispose();
    super.dispose();
  }

  // Re-check when the user returns from Android Settings.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _checkStatus();
    }
  }

  Future<void> _checkStatus() async {
    try {
      final enabled =
          await _channel.invokeMethod<bool>('isNotificationListenerEnabled') ??
              false;
      if (mounted) {
        setState(() {
          _isEnabled = enabled;
          _isChecking = false;
        });
      }
    } on MissingPluginException {
      // Running on web/desktop — service unavailable.
      if (mounted) {
        setState(() {
          _isEnabled = false;
          _isChecking = false;
        });
      }
    }
  }

  Future<void> _openSettings() async {
    try {
      await _channel.invokeMethod('openNotificationListenerSettings');
    } catch (_) {
      // Fail silently.
    }
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
      child: Column(
        children: [
          const SizedBox(height: 16),
          _heroIcon(),
          const SizedBox(height: 28),
          _title(),
          const SizedBox(height: 8),
          _subtitle(),
          const SizedBox(height: 32),
          _statusCard(),
          const SizedBox(height: 20),
          _enableButton(),
          const SizedBox(height: 28),
          _channelList(),
          const SizedBox(height: 24),
          _infoCard(),
        ],
      ),
    );
  }

  // ── Animated hero icon ──
  Widget _heroIcon() => AnimatedBuilder(
        animation: _pulse,
        builder: (_, __) => Container(
          width: 110,
          height: 110,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            gradient: RadialGradient(
              colors: [
                (_isEnabled ? const Color(0xFF00FFA3) : const Color(0xFFFF9F1C))
                    .withOpacity(0.15 * _pulse.value),
                Colors.transparent,
              ],
            ),
            border: Border.all(
              color: (_isEnabled
                      ? const Color(0xFF00FFA3)
                      : const Color(0xFFFF9F1C))
                  .withOpacity(0.4 * _pulse.value),
              width: 2,
            ),
            boxShadow: [
              BoxShadow(
                color: (_isEnabled
                        ? const Color(0xFF00FFA3)
                        : const Color(0xFFFF9F1C))
                    .withOpacity(0.15 * _pulse.value),
                blurRadius: 30,
                spreadRadius: 5,
              ),
            ],
          ),
          child: Icon(
            _isEnabled
                ? Icons.verified_user_rounded
                : Icons.shield_outlined,
            color:
                _isEnabled ? const Color(0xFF00FFA3) : const Color(0xFFFF9F1C),
            size: 50,
          ),
        ),
      );

  // ── Title ──
  Widget _title() => Text(
        'OMNI-CHANNEL SHIELD',
        style: GoogleFonts.orbitron(
          color: Colors.white,
          fontSize: 18,
          fontWeight: FontWeight.w800,
          letterSpacing: 3,
        ),
      );

  // ── Subtitle ──
  Widget _subtitle() => Text(
        'Real-time phishing detection across\nSMS, WhatsApp, Telegram, Signal & more.',
        textAlign: TextAlign.center,
        style: TextStyle(
          color: Colors.white.withOpacity(0.5),
          fontSize: 13,
          height: 1.6,
        ),
      );

  // ── Status indicator card ──
  Widget _statusCard() {
    if (_isChecking) {
      return _statusChip(
        'CHECKING…',
        const Color(0xFF00D4FF),
        Icons.hourglass_top_rounded,
      );
    }
    return _isEnabled
        ? _statusChip(
            'SHIELD ACTIVE',
            const Color(0xFF00FFA3),
            Icons.check_circle_rounded,
          )
        : _statusChip(
            'SHIELD INACTIVE',
            const Color(0xFFFF4D4D),
            Icons.error_outline_rounded,
          );
  }

  Widget _statusChip(String label, Color color, IconData icon) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: color.withOpacity(0.08),
          border: Border.all(color: color.withOpacity(0.25)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: color, size: 18),
            const SizedBox(width: 10),
            Text(
              label,
              style: GoogleFonts.orbitron(
                color: color,
                fontSize: 12,
                fontWeight: FontWeight.w700,
                letterSpacing: 2,
              ),
            ),
          ],
        ),
      );

  // ── Enable / Open Settings button ──
  Widget _enableButton() => GestureDetector(
        onTap: _openSettings,
        child: AnimatedBuilder(
          animation: _pulse,
          builder: (_, __) => Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 18),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(16),
              gradient: _isEnabled
                  ? LinearGradient(colors: [
                      const Color(0xFF00FFA3).withOpacity(0.15),
                      const Color(0xFF00D4FF).withOpacity(0.10),
                    ])
                  : LinearGradient(colors: [
                      const Color(0xFFFF9F1C),
                      Color.lerp(
                        const Color(0xFFFF6B00),
                        const Color(0xFFFF9F1C),
                        _pulse.value,
                      )!,
                    ]),
              boxShadow: _isEnabled
                  ? []
                  : [
                      BoxShadow(
                        color:
                            const Color(0xFFFF9F1C).withOpacity(0.3 * _pulse.value),
                        blurRadius: 16,
                        spreadRadius: 1,
                        offset: const Offset(0, 4),
                      ),
                    ],
              border: _isEnabled
                  ? Border.all(
                      color: const Color(0xFF00FFA3).withOpacity(0.2))
                  : null,
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  _isEnabled ? Icons.settings_rounded : Icons.security_rounded,
                  color: _isEnabled
                      ? const Color(0xFF00FFA3)
                      : Colors.white,
                  size: 22,
                ),
                const SizedBox(width: 12),
                Text(
                  _isEnabled
                      ? 'OPEN NOTIFICATION SETTINGS'
                      : 'ENABLE OMNI-CHANNEL SHIELD',
                  style: GoogleFonts.orbitron(
                    color: _isEnabled
                        ? const Color(0xFF00FFA3)
                        : Colors.white,
                    fontSize: 12,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 1.5,
                  ),
                ),
              ],
            ),
          ),
        ),
      );

  // ── Protected channels list ──
  Widget _channelList() => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(16),
          color: Colors.white.withOpacity(0.03),
          border: Border.all(color: Colors.white.withOpacity(0.08)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'PROTECTED CHANNELS',
              style: GoogleFonts.orbitron(
                color: Colors.white.withOpacity(0.6),
                fontSize: 10,
                fontWeight: FontWeight.w700,
                letterSpacing: 2,
              ),
            ),
            const SizedBox(height: 14),
            _channelRow(Icons.sms_rounded, 'SMS / MMS', 'All SMS apps'),
            _channelRow(Icons.chat_rounded, 'WhatsApp', 'Personal & Business'),
            _channelRow(Icons.send_rounded, 'Telegram', 'Chats & Channels'),
            _channelRow(Icons.lock_rounded, 'Signal', 'End-to-end encrypted'),
            _channelRow(
                Icons.facebook_rounded, 'Messenger', 'Facebook messages'),
            _channelRow(Icons.more_horiz_rounded, 'All Others',
                'Any app with notifications'),
          ],
        ),
      );

  Widget _channelRow(IconData icon, String name, String desc) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Row(
          children: [
            Container(
              width: 34,
              height: 34,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(10),
                color: const Color(0xFF00FFA3).withOpacity(0.08),
              ),
              child: Icon(icon, color: const Color(0xFF00FFA3), size: 16),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    name,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  Text(
                    desc,
                    style: TextStyle(
                      color: Colors.white.withOpacity(0.35),
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
            Icon(
              _isEnabled
                  ? Icons.check_circle_rounded
                  : Icons.radio_button_unchecked_rounded,
              color: _isEnabled
                  ? const Color(0xFF00FFA3)
                  : Colors.white.withOpacity(0.15),
              size: 18,
            ),
          ],
        ),
      );

  // ── How it works info card ──
  Widget _infoCard() => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: const Color(0xFF00D4FF).withOpacity(0.05),
          border: Border.all(color: const Color(0xFF00D4FF).withOpacity(0.12)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.info_outline_rounded,
                  color: const Color(0xFF00D4FF).withOpacity(0.7),
                  size: 16,
                ),
                const SizedBox(width: 8),
                Text(
                  'HOW IT WORKS',
                  style: GoogleFonts.orbitron(
                    color: const Color(0xFF00D4FF).withOpacity(0.7),
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 1.5,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Text(
              '1.  Reads notification text from any messaging app\n'
              '2.  Extracts URLs and sends to KAVACH backend\n'
              '3.  Heuristic engine checks for brand spoofing,\n'
              '     homoglyphs, and high-risk TLDs\n'
              '4.  Fires instant alert if phishing is detected',
              style: TextStyle(
                color: Colors.white.withOpacity(0.45),
                fontSize: 12,
                height: 1.7,
              ),
            ),
          ],
        ),
      );
}
