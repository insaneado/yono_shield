// ============================================================================
// YONO SHIELD — Red Alert Overlay (Audio-Visual Threat Education)
// ============================================================================
//
// A full-screen, unmissable red modal triggered when a threat is detected.
//
// Designed for rural, low-literacy users:
//   - Massive pulsing "Play Audio" button with speaker icon
//   - TTS reads the warning aloud in simple, conversational language
//   - Large universal icons (shield, thief, lock) replace text-heavy warnings
//   - Extremely high-contrast UI (white on deep red gradient)
//   - Auto-speaks the warning on open for zero-interaction education
//
// Handles:
//   - ROOTED_DEVICE:             "Device OS Compromised (Root Detected)"
//   - TROJAN_DETECTED_<AppName>: Malicious overlay or accessibility app
//   - INVALID_SIGNATURE:         "Brand Impersonation Blocked"
// ============================================================================

import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_tts/flutter_tts.dart';
import 'package:http/http.dart' as http;
import '../services/security_bridge.dart';

// ── Telemetry helper (silent, fire-and-forget) ──
Future<void> _reportFraudSilently(String badPackage, String threatType) async {
  const telemetryUrl = 'http://10.0.2.2:8080/api/telemetry';
  try {
    await http.post(
      Uri.parse(telemetryUrl),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode({
        'device_id': 'yono_shield_device_01',
        'package_name': badPackage,
        'threat_type': threatType,
        'timestamp': DateTime.now().toIso8601String(),
      }),
    );
  } catch (_) {
    // Silent — backend may be offline during demo.
  }
}

// ============================================================================
// CONVENIENCE LAUNCHER — call from any page to show the Red Alert
// ============================================================================
void showRedAlertOverlay(BuildContext context, Map<String, dynamic> result) {
  final verdict = result['verdict'] as String? ?? '';
  final trojanAppName = verdict.startsWith('TROJAN_DETECTED_')
      ? ((result['trojanApp'] as String?)?.trim().isNotEmpty ?? false)
          ? (result['trojanApp'] as String).trim()
          : verdict.split('TROJAN_DETECTED_').last.trim()
      : null;

  late String alertTitle;
  late String alertSubtitle;
  late String alertMessage;
  late IconData alertIcon;

  if (trojanAppName != null && trojanAppName.isNotEmpty) {
    alertTitle = 'RED ALERT';
    alertSubtitle = 'TROJAN OVERLAY DETECTED';
    alertMessage =
        "\u{1F6A8} TROJAN DETECTED: '$trojanAppName' has malicious "
        'screen-reading permissions. Uninstall immediately to unlock YONO.';
    alertIcon = Icons.pest_control_rounded;
  } else {
    switch (verdict) {
      case 'ROOTED_DEVICE':
        alertTitle = 'CRITICAL';
        alertSubtitle = 'DEVICE OS COMPROMISED';
        alertMessage =
            '🚨 CRITICAL: Device OS Compromised (Root Detected). '
            'YONO Operations Locked.\n\n'
            'Root access was detected on this device, which allows '
            'malicious actors to bypass OS-level security controls, '
            'intercept banking transactions, and capture credentials.\n\n'
            'All YONO banking operations are SUSPENDED until the '
            'device is restored to a verified, unmodified state.';
        alertIcon = Icons.phonelink_lock_rounded;
        break;
      case 'INVALID_SIGNATURE':
        alertTitle = 'THREAT DETECTED';
        alertSubtitle = 'UNOFFICIAL APP SIGNATURE';
        alertMessage =
            '🚨 THREAT DETECTED: Unofficial App Signature. '
            'Brand Impersonation Blocked.\n\n'
            'This app is signed with a DIFFERENT cryptographic key '
            'than the official version published by the bank.\n\n'
            'It may be a MALICIOUS CLONE designed to steal your '
            'banking credentials, OTP codes, and personal data.';
        alertIcon = Icons.gpp_bad_rounded;
        break;
      default:
        alertTitle = 'SECURITY ALERT';
        alertSubtitle = verdict.replaceAll('_', ' ');
        alertMessage =
            result['message']?.toString() ?? 'Unknown threat detected.';
        alertIcon = Icons.warning_amber_rounded;
    }
  }

  showGeneralDialog(
    context: context,
    barrierDismissible: false,
    barrierColor: Colors.black87,
    transitionDuration: const Duration(milliseconds: 400),
    transitionBuilder: (ctx, a1, a2, child) => FadeTransition(
      opacity: a1,
      child: ScaleTransition(scale: a1, child: child),
    ),
    pageBuilder: (ctx, _, __) => RedAlertOverlay(
      title: alertTitle,
      subtitle: alertSubtitle,
      message: alertMessage,
      icon: alertIcon,
      result: result,
    ),
  );
}

// ============================================================================
// RED ALERT OVERLAY — The full-screen audio-visual warning widget
// ============================================================================
class RedAlertOverlay extends StatefulWidget {
  final String title;
  final String subtitle;
  final String message;
  final IconData icon;
  final Map<String, dynamic> result;

  const RedAlertOverlay({
    super.key,
    required this.title,
    required this.subtitle,
    required this.message,
    required this.icon,
    required this.result,
  });

  @override
  State<RedAlertOverlay> createState() => _RedAlertOverlayState();
}

class _RedAlertOverlayState extends State<RedAlertOverlay>
    with TickerProviderStateMixin {
  final SecurityBridge _bridge = SecurityBridge();
  final FlutterTts _tts = FlutterTts();

  late AnimationController _pulse;
  late Animation<double> _pulseAnim;
  late AnimationController _speakerPulse;
  late Animation<double> _speakerScale;

  bool _didReportFraud = false;
  bool _isLaunchingUninstall = false;
  bool _isSpeaking = false;

  @override
  void initState() {
    super.initState();

    // Background pulse for the entire red gradient
    _pulse = AnimationController(
      duration: const Duration(milliseconds: 800),
      vsync: this,
    )..repeat(reverse: true);
    _pulseAnim = Tween<double>(begin: 0.6, end: 1.0).animate(
      CurvedAnimation(parent: _pulse, curve: Curves.easeInOut),
    );

    // Dedicated speaker button pulse — slower, more attention-grabbing
    _speakerPulse = AnimationController(
      duration: const Duration(milliseconds: 1200),
      vsync: this,
    )..repeat(reverse: true);
    _speakerScale = Tween<double>(begin: 0.92, end: 1.08).animate(
      CurvedAnimation(parent: _speakerPulse, curve: Curves.easeInOut),
    );

    WidgetsBinding.instance.addPostFrameCallback((_) {
      _reportThreatOnce();
      // Auto-speak warning on open — critical for low-literacy users
      Future.delayed(const Duration(milliseconds: 600), _speakWarning);
    });
    _initTts();
  }

  Future<void> _initTts() async {
    await _tts.setLanguage('en-IN');
    await _tts.setSpeechRate(0.45);
    await _tts.setVolume(1.0);
    await _tts.setPitch(1.0);
    _tts.setStartHandler(() {
      if (mounted) setState(() => _isSpeaking = true);
    });
    _tts.setCompletionHandler(() {
      if (mounted) setState(() => _isSpeaking = false);
    });
    _tts.setErrorHandler((msg) {
      if (mounted) setState(() => _isSpeaking = false);
    });
  }

  String _getTtsMessage() {
    final verdict = widget.result['verdict'] as String? ?? '';
    if (verdict.startsWith('TROJAN_DETECTED_')) {
      final trojanApp = widget.result['trojanApp']?.toString() ?? 'this app';
      return 'Warning. $trojanApp is trying to read your screen to steal your '
          'OTP. Please press the uninstall button below.';
    }
    if (verdict == 'ROOTED_DEVICE') {
      return 'Warning. Your phone has been modified. This makes your banking '
          'app unsafe. Please take your phone to a service center to fix this.';
    }
    if (verdict == 'INVALID_SIGNATURE') {
      return 'Warning. This app is a fake copy of your banking app. It will '
          'steal your password. Please delete it immediately.';
    }
    return 'Warning. A security threat has been found on your phone. Please '
        'contact your bank for help.';
  }

  Future<void> _speakWarning() async {
    if (_isSpeaking) {
      await _tts.stop();
      return;
    }
    await _tts.speak(_getTtsMessage());
  }

  @override
  void dispose() {
    _tts.stop();
    _pulse.dispose();
    _speakerPulse.dispose();
    super.dispose();
  }

  void _reportThreatOnce() {
    if (_didReportFraud) return;
    final badPackage = _threatPackageName(widget.result);
    final threatType = _threatType(widget.result);
    if (badPackage.isEmpty || threatType.isEmpty) return;
    _didReportFraud = true;
    unawaited(_reportFraudSilently(badPackage, threatType));
  }

  String _threatPackageName(Map<String, dynamic> result) {
    final verdict = result['verdict'] as String? ?? '';
    if (verdict.startsWith('TROJAN_DETECTED_')) {
      return (result['trojanPackage'] as String? ?? '').trim();
    }
    return (result['packageName'] as String? ?? '').trim();
  }

  String _threatType(Map<String, dynamic> result) {
    final verdict = result['verdict'] as String? ?? '';
    if (verdict.startsWith('TROJAN_DETECTED_')) return 'TROJAN_DETECTED';
    return verdict;
  }

  Future<void> _uninstallThreat(String packageName) async {
    if (_isLaunchingUninstall || packageName.isEmpty) return;
    setState(() => _isLaunchingUninstall = true);
    try {
      await _bridge.uninstallApp(packageName);
    } catch (_) {
      // Keep the overlay stable if the Android uninstaller cannot be opened.
    } finally {
      if (mounted) setState(() => _isLaunchingUninstall = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final r = widget.result;
    final verdict = r['verdict'] as String? ?? '';
    final trojanApp = verdict.startsWith('TROJAN_DETECTED_')
        ? ((r['trojanApp'] as String?)?.trim().isNotEmpty ?? false)
            ? (r['trojanApp'] as String).trim()
            : verdict.split('TROJAN_DETECTED_').last.trim()
        : null;
    final uninstallPackage = _threatPackageName(r);
    final canUninstallThreat =
        uninstallPackage.isNotEmpty && verdict != 'ROOTED_DEVICE';
    final liveHash = r['liveHash']?.toString();
    final expectedHash = r['expectedHash']?.toString();

    return Material(
      color: Colors.transparent,
      child: AnimatedBuilder(
        animation: _pulseAnim,
        builder: (_, __) => Container(
          width: double.infinity,
          height: double.infinity,
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                const Color(0xFF1A0000),
                Color.lerp(
                  const Color(0xFF4D0000),
                  const Color(0xFF990000),
                  _pulseAnim.value,
                )!,
                const Color(0xFFCC0000),
              ],
            ),
          ),
          child: SafeArea(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 20),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const SizedBox(height: 12),

                  // ── Warning icon with glow ──
                  _buildMainIcon(),
                  const SizedBox(height: 24),

                  // ── Title ──
                  Text(
                    widget.title,
                    style: GoogleFonts.orbitron(
                      color: Colors.white,
                      fontSize: 28,
                      fontWeight: FontWeight.w900,
                      letterSpacing: 4,
                    ),
                  ),
                  const SizedBox(height: 10),

                  // ── Subtitle badge ──
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 8,
                    ),
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(8),
                      color: Colors.white.withOpacity(0.15),
                    ),
                    child: Text(
                      widget.subtitle,
                      style: GoogleFonts.orbitron(
                        color: Colors.white,
                        fontSize: 11,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 2,
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),

                  // ── Large Universal Icons Row ──
                  _buildUniversalIcons(verdict),
                  const SizedBox(height: 20),

                  // ── MASSIVE PLAY AUDIO BUTTON ──
                  _buildPlayAudioButton(),
                  const SizedBox(height: 20),

                  // ── Message body ──
                  Text(
                    widget.message,
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: Colors.white.withOpacity(0.85),
                      fontSize: 13,
                      height: 1.6,
                    ),
                  ),
                  const SizedBox(height: 24),

                  // ── Hash details (INVALID_SIGNATURE only) ──
                  if (verdict == 'INVALID_SIGNATURE' &&
                      liveHash != null &&
                      expectedHash != null)
                    _buildHashDetails(r, liveHash, expectedHash),

                  // ── Root details (ROOTED_DEVICE only) ──
                  if (verdict == 'ROOTED_DEVICE') _buildRootDetails(),

                  // ── Trojan details ──
                  if (trojanApp != null && trojanApp.isNotEmpty)
                    _buildTrojanDetails(trojanApp),

                  const SizedBox(height: 28),

                  // ── UNINSTALL THREAT NOW button ──
                  if (canUninstallThreat)
                    _buildUninstallButton(uninstallPackage),

                  // ── Dismiss button ──
                  _buildDismissButton(),
                  const SizedBox(height: 16),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  // ── Main threat icon with animated glow ──
  Widget _buildMainIcon() {
    return AnimatedBuilder(
      animation: _pulseAnim,
      builder: (_, __) => Container(
        width: 110,
        height: 110,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: Colors.red.withOpacity(0.2),
          boxShadow: [
            BoxShadow(
              color: const Color(0xFFFF4D4D)
                  .withOpacity(0.4 * _pulseAnim.value),
              blurRadius: 40,
              spreadRadius: 10,
            ),
          ],
        ),
        child: Icon(widget.icon, color: Colors.white, size: 60),
      ),
    );
  }

  // ── Large universal icons replacing text-heavy warnings ──
  Widget _buildUniversalIcons(String verdict) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: [
          _universalIcon(
            Icons.shield_rounded,
            'PROTECT',
            const Color(0xFFFF6B6B),
          ),
          _universalIcon(
            verdict.startsWith('TROJAN_DETECTED_')
                ? Icons.pest_control_rounded
                : verdict == 'ROOTED_DEVICE'
                    ? Icons.phonelink_lock_rounded
                    : Icons.person_off_rounded,
            verdict.startsWith('TROJAN_DETECTED_')
                ? 'THIEF APP'
                : verdict == 'ROOTED_DEVICE'
                    ? 'UNSAFE'
                    : 'FAKE APP',
            Colors.white,
          ),
          _universalIcon(
            Icons.lock_rounded,
            'LOCKED',
            const Color(0xFFFFD93D),
          ),
        ],
      ),
    );
  }

  // ── MASSIVE pulsing Play Audio button ──
  Widget _buildPlayAudioButton() {
    return GestureDetector(
      onTap: _speakWarning,
      child: AnimatedBuilder(
        animation: _speakerScale,
        builder: (_, __) => Transform.scale(
          scale: _speakerScale.value,
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 22),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(20),
              gradient: LinearGradient(
                colors: _isSpeaking
                    ? [
                        const Color(0xFFFF6B00).withOpacity(0.35),
                        const Color(0xFFFF3300).withOpacity(0.20),
                      ]
                    : [
                        Colors.white.withOpacity(0.20),
                        Colors.white.withOpacity(0.08),
                      ],
              ),
              border: Border.all(
                color: _isSpeaking
                    ? const Color(0xFFFF6B00).withOpacity(0.6)
                    : Colors.white.withOpacity(0.35),
                width: 2.5,
              ),
              boxShadow: [
                BoxShadow(
                  color: (_isSpeaking
                          ? const Color(0xFFFF6B00)
                          : Colors.white)
                      .withOpacity(0.15 * _speakerScale.value),
                  blurRadius: 30,
                  spreadRadius: 4,
                ),
              ],
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Massive speaker icon
                Icon(
                  _isSpeaking
                      ? Icons.stop_circle_rounded
                      : Icons.volume_up_rounded,
                  color: Colors.white,
                  size: 48,
                ),
                const SizedBox(width: 16),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      _isSpeaking ? 'STOP AUDIO' : 'PLAY AUDIO WARNING',
                      style: GoogleFonts.orbitron(
                        color: Colors.white,
                        fontSize: 15,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.5,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      _isSpeaking
                          ? '🔊 Speaking… Tap to stop'
                          : '🔊 Tap to hear this warning',
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.6),
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ── Hash mismatch details box ──
  Widget _buildHashDetails(
    Map<String, dynamic> r,
    String liveHash,
    String expectedHash,
  ) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: Colors.black.withOpacity(0.3),
          border: Border.all(color: Colors.white.withOpacity(0.15)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _detailRow('PACKAGE', r['packageName']?.toString() ?? ''),
            const SizedBox(height: 8),
            _detailRow('VERDICT', 'SIGNATURE MISMATCH'),
            const Divider(color: Colors.white24, height: 24),
            _hashDetail('LIVE SHA-256', liveHash),
            const SizedBox(height: 8),
            _hashDetail('EXPECTED', expectedHash),
          ],
        ),
      ),
    );
  }

  // ── Root detection details box ──
  Widget _buildRootDetails() {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: Colors.black.withOpacity(0.3),
          border: Border.all(color: Colors.white.withOpacity(0.15)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _detailRow('STATUS', 'ROOT DETECTED'),
            const SizedBox(height: 8),
            _detailRow('RESOLUTION', 'Restore device to factory state'),
            const SizedBox(height: 8),
            _detailRow('OPERATIONS', 'LOCKED'),
          ],
        ),
      ),
    );
  }

  // ── Trojan details box ──
  Widget _buildTrojanDetails(String trojanApp) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: Colors.black.withOpacity(0.3),
          border: Border.all(color: Colors.white.withOpacity(0.15)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _detailRow('STATUS', 'TROJAN OVERLAY'),
            const SizedBox(height: 8),
            _detailRow('APP', trojanApp),
            const SizedBox(height: 8),
            _detailRow('ACTION', 'Uninstall immediately'),
          ],
        ),
      ),
    );
  }

  // ── Pulsing Uninstall button ──
  Widget _buildUninstallButton(String uninstallPackage) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 14),
      child: GestureDetector(
        onTap: _isLaunchingUninstall
            ? null
            : () => _uninstallThreat(uninstallPackage),
        child: AnimatedBuilder(
          animation: _pulseAnim,
          builder: (_, __) => Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 18),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(14),
              gradient: LinearGradient(
                colors: [
                  const Color(0xFFFF4D4D),
                  Color.lerp(
                    const Color(0xFFFF6B00),
                    const Color(0xFFFF3300),
                    _pulseAnim.value,
                  )!,
                ],
              ),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFFFF4D4D)
                      .withOpacity(0.5 * _pulseAnim.value),
                  blurRadius: 20,
                  spreadRadius: 2,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                if (_isLaunchingUninstall) ...[
                  const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      strokeWidth: 2.5,
                      color: Colors.white,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Text(
                    'LAUNCHING UNINSTALLER…',
                    style: GoogleFonts.orbitron(
                      color: Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 1.5,
                    ),
                  ),
                ] else ...[
                  const Icon(Icons.delete_forever_rounded,
                      color: Colors.white, size: 22),
                  const SizedBox(width: 10),
                  Text(
                    'UNINSTALL THREAT NOW',
                    style: GoogleFonts.orbitron(
                      color: Colors.white,
                      fontSize: 14,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 1.5,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ── Dismiss button ──
  Widget _buildDismissButton() {
    return GestureDetector(
      onTap: () => Navigator.of(context).pop(),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(vertical: 16),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: Colors.white,
          boxShadow: [
            BoxShadow(
              color: Colors.white.withOpacity(0.3),
              blurRadius: 16,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: const Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.close_rounded, color: Color(0xFFCC0000), size: 20),
            SizedBox(width: 8),
            Text(
              'ACKNOWLEDGE & DISMISS',
              style: TextStyle(
                color: Color(0xFFCC0000),
                fontSize: 15,
                fontWeight: FontWeight.w800,
                letterSpacing: 1.5,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── Helper widgets ──

  Widget _detailRow(String label, String value) => Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 90,
            child: Text(
              label,
              style: TextStyle(
                color: Colors.white.withOpacity(0.5),
                fontSize: 11,
                fontWeight: FontWeight.w700,
                letterSpacing: 1,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 13,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      );

  Widget _hashDetail(String label, String hash) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: TextStyle(
              color: Colors.white.withOpacity(0.4),
              fontSize: 9,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.5,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            hash,
            style: TextStyle(
              color: Colors.white.withOpacity(0.7),
              fontSize: 10,
              fontFamily: 'monospace',
              height: 1.4,
            ),
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      );

  Widget _universalIcon(IconData icon, String label, Color color) {
    return Column(
      children: [
        Container(
          width: 64,
          height: 64,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: color.withOpacity(0.15),
            border: Border.all(color: color.withOpacity(0.4), width: 2),
            boxShadow: [
              BoxShadow(
                color: color.withOpacity(0.2),
                blurRadius: 12,
                spreadRadius: 2,
              ),
            ],
          ),
          child: Icon(icon, color: color, size: 34),
        ),
        const SizedBox(height: 6),
        Text(
          label,
          style: TextStyle(
            color: color.withOpacity(0.8),
            fontSize: 9,
            fontWeight: FontWeight.w800,
            letterSpacing: 1,
          ),
        ),
      ],
    );
  }
}
