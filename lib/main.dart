// ============================================================================
// YONO SHIELD — main.dart (v3 — Cryptographic Gatekeeper)
// ============================================================================
//
// Entry point for the YONO Shield cybersecurity app.
//
// Architecture:
//   ┌─────────────────────────────────────────────────────┐
//   │  Flutter UI (this file)                             │
//   │    ├─ SecurityDashboard (scaffold + bottom nav)     │
//   │    ├─ RadarPage  → Cryptographic Gatekeeper scan    │
//   │    ├─ SmsPage    → SMS Interceptor                  │
//   │    ├─ OverlayPage→ Threat Shield                    │
//   │    └─ _ThreatAlert (full-screen red modal)          │
//   │              │                                      │
//   │       MethodChannel                                 │
//   │              │                                      │
//   │  Kotlin Native (MainActivity.kt)                    │
//   │    ├─ isDeviceRooted()          → root detection    │
//   │    ├─ getAppSignatureHash(pkg)  → SHA-256           │
//   │    └─ verifyAppSecurity(pkg)    → gatekeeper        │
//   └─────────────────────────────────────────────────────┘
// ============================================================================

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:http/http.dart' as http;
import 'pages/clone_radar_page.dart';
import 'pages/sms_interceptor_page.dart';
import 'pages/overlay_control_page.dart';
import 'services/security_bridge.dart';

Future<void> reportFraudSilently(String badPackage, String threatType) async {
  // ── KAVACH Telemetry Bridge ──
  // For Android Emulator → host machine: http://10.0.2.2:8080/api/telemetry
  // For Ngrok tunnel (demo): https://YOUR_NGROK_ID.ngrok-free.app/api/telemetry
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
    // Silent by design — backend may be offline during demo.
    // The Red Alert UI must never freeze for a network call.
  }
}

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  SystemChrome.setPreferredOrientations([DeviceOrientation.portraitUp]);
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.light,
      systemNavigationBarColor: Color(0xFF080C18),
      systemNavigationBarIconBrightness: Brightness.light,
    ),
  );
  runApp(const YonoShieldApp());
}

// ============================================================================
// APP ROOT
// ============================================================================
class YonoShieldApp extends StatelessWidget {
  const YonoShieldApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'YONO Shield',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0B101E),
        primaryColor: const Color(0xFF00FFA3),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00FFA3),
          secondary: Color(0xFF00D4FF),
          surface: Color(0xFF111827),
          error: Color(0xFFFF4D4D),
        ),
        textTheme: GoogleFonts.interTextTheme(ThemeData.dark().textTheme),
        useMaterial3: true,
      ),
      home: const SecurityDashboard(),
    );
  }
}

// ============================================================================
// SECURITY DASHBOARD — scaffold + bottom nav + alert trigger
// ============================================================================
class SecurityDashboard extends StatefulWidget {
  const SecurityDashboard({super.key});
  @override
  State<SecurityDashboard> createState() => _SecurityDashboardState();
}

class _SecurityDashboardState extends State<SecurityDashboard>
    with TickerProviderStateMixin {
  int _tab = 0;
  late PageController _pageCtrl;
  late AnimationController _shieldPulse;
  late Animation<double> _glow;

  @override
  void initState() {
    super.initState();
    _pageCtrl = PageController();
    _shieldPulse = AnimationController(
      duration: const Duration(seconds: 3),
      vsync: this,
    )..repeat(reverse: true);
    _glow = Tween<double>(
      begin: 0.4,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _shieldPulse, curve: Curves.easeInOut));
  }

  @override
  void dispose() {
    _pageCtrl.dispose();
    _shieldPulse.dispose();
    super.dispose();
  }

  void _goTab(int i) {
    setState(() => _tab = i);
    _pageCtrl.animateToPage(
      i,
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeInOut,
    );
  }

  // ── Called by RadarPage when a threat is detected ──
  // Handles root, trojan overlay, and invalid-signature verdicts.
  void _showThreatAlert(Map<String, dynamic> result) {
    final verdict = result['verdict'] as String? ?? '';
    final trojanAppName =
        verdict.startsWith('TROJAN_DETECTED_')
            ? ((result['trojanApp'] as String?)?.trim().isNotEmpty ?? false)
                ? (result['trojanApp'] as String).trim()
                : verdict.split('TROJAN_DETECTED_').last.trim()
            : null;

    // Determine alert content based on verdict type
    late String alertTitle;
    late String alertSubtitle;
    late String alertMessage;
    late IconData alertIcon;

    if (trojanAppName != null && trojanAppName.isNotEmpty) {
      showGeneralDialog(
        context: context,
        barrierDismissible: false,
        barrierColor: Colors.black87,
        transitionDuration: const Duration(milliseconds: 400),
        transitionBuilder:
            (ctx, a1, a2, child) => FadeTransition(
              opacity: a1,
              child: ScaleTransition(scale: a1, child: child),
            ),
        pageBuilder:
            (ctx, _, __) => _ThreatAlert(
              title: 'RED ALERT',
              subtitle: 'TROJAN OVERLAY DETECTED',
              message:
                  "\u{1F6A8} TROJAN DETECTED: '$trojanAppName' has malicious "
                  'screen-reading permissions. Uninstall immediately to unlock YONO.',
              icon: Icons.pest_control_rounded,
              result: result,
            ),
      );
      return;
    }

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

    showGeneralDialog(
      context: context,
      barrierDismissible: false,
      barrierColor: Colors.black87,
      transitionDuration: const Duration(milliseconds: 400),
      transitionBuilder:
          (ctx, a1, a2, child) => FadeTransition(
            opacity: a1,
            child: ScaleTransition(scale: a1, child: child),
          ),
      pageBuilder:
          (ctx, _, __) => _ThreatAlert(
            title: alertTitle,
            subtitle: alertSubtitle,
            message: alertMessage,
            icon: alertIcon,
            result: result,
          ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0B101E),
      body: Column(
        children: [
          _header(),
          Expanded(
            child: PageView(
              controller: _pageCtrl,
              onPageChanged: (i) => setState(() => _tab = i),
              children: [
                RadarPage(onThreatDetected: _showThreatAlert),
                const SmsPage(),
                const OverlayPage(),
              ],
            ),
          ),
        ],
      ),
      bottomNavigationBar: _bottomNav(),
    );
  }

  // ── Gradient Header ──
  Widget _header() => Container(
    width: double.infinity,
    padding: EdgeInsets.only(
      top: MediaQuery.of(context).padding.top + 12,
      bottom: 16,
      left: 20,
      right: 20,
    ),
    decoration: const BoxDecoration(
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [Color(0xFF0F1629), Color(0xFF0B101E)],
      ),
      border: Border(bottom: BorderSide(color: Color(0xFF1A2035))),
    ),
    child: Row(
      children: [
        AnimatedBuilder(
          animation: _glow,
          builder:
              (_, __) => Container(
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: RadialGradient(
                    colors: [
                      const Color(0xFF00FFA3).withOpacity(0.2 * _glow.value),
                      Colors.transparent,
                    ],
                  ),
                  border: Border.all(
                    color: const Color(
                      0xFF00FFA3,
                    ).withOpacity(0.3 * _glow.value),
                    width: 1.5,
                  ),
                ),
                child: Icon(
                  Icons.shield_rounded,
                  color: Color.lerp(
                    const Color(0xFF00FFA3).withOpacity(0.5),
                    const Color(0xFF00FFA3),
                    _glow.value,
                  ),
                  size: 24,
                ),
              ),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'YONO SHIELD',
                style: GoogleFonts.orbitron(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 3,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                [
                  'CRYPTO GATEKEEPER • SIGNATURE RADAR',
                  'OMNI-CHANNEL SHIELD • PHISHING GUARD',
                  'THREAT SHIELD • BLOCK OVERLAY',
                ][_tab],
                style: TextStyle(
                  color: Colors.white.withOpacity(0.4),
                  fontSize: 11,
                  letterSpacing: 1,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
        Container(
          width: 10,
          height: 10,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: const Color(0xFF00FFA3),
            boxShadow: [
              BoxShadow(
                color: const Color(0xFF00FFA3).withOpacity(0.5),
                blurRadius: 8,
                spreadRadius: 2,
              ),
            ],
          ),
        ),
        const SizedBox(width: 6),
        Text(
          'ACTIVE',
          style: TextStyle(
            color: const Color(0xFF00FFA3).withOpacity(0.7),
            fontSize: 10,
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
          ),
        ),
      ],
    ),
  );

  // ── Bottom Nav ──
  Widget _bottomNav() => Container(
    decoration: const BoxDecoration(
      color: Color(0xFF080C18),
      border: Border(top: BorderSide(color: Color(0xFF1A2035))),
    ),
    child: SafeArea(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceAround,
          children: [
            _navItem(0, Icons.fingerprint_rounded, 'RADAR'),
            _navItem(1, Icons.shield_rounded, 'SHIELD'),
            _navItem(2, Icons.layers_rounded, 'OVERLAY'),
          ],
        ),
      ),
    ),
  );

  Widget _navItem(int i, IconData icon, String label) {
    final sel = _tab == i;
    return GestureDetector(
      onTap: () => _goTab(i),
      behavior: HitTestBehavior.opaque,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color:
              sel
                  ? const Color(0xFF00FFA3).withOpacity(0.1)
                  : Colors.transparent,
          border:
              sel
                  ? Border.all(color: const Color(0xFF00FFA3).withOpacity(0.2))
                  : null,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              color:
                  sel ? const Color(0xFF00FFA3) : Colors.white.withOpacity(0.3),
              size: 24,
            ),
            const SizedBox(height: 4),
            Text(
              label,
              style: TextStyle(
                color:
                    sel
                        ? const Color(0xFF00FFA3)
                        : Colors.white.withOpacity(0.3),
                fontSize: 9,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ============================================================================
// 🚨 THREAT ALERT — Full-screen unmissable red modal
// ============================================================================
// Handles:
//   - ROOTED_DEVICE:             "Device OS Compromised (Root Detected)"
//   - TROJAN_DETECTED_<AppName>: Malicious overlay or accessibility app
//   - INVALID_SIGNATURE:         "Unofficial App Signature. Brand Impersonation Blocked."
// ============================================================================
class _ThreatAlert extends StatefulWidget {
  final String title;
  final String subtitle;
  final String message;
  final IconData icon;
  final Map<String, dynamic> result;

  const _ThreatAlert({
    required this.title,
    required this.subtitle,
    required this.message,
    required this.icon,
    required this.result,
  });

  @override
  State<_ThreatAlert> createState() => _ThreatAlertState();
}

class _ThreatAlertState extends State<_ThreatAlert>
    with SingleTickerProviderStateMixin {
  final SecurityBridge _bridge = SecurityBridge();
  late AnimationController _pulse;
  late Animation<double> _pulseAnim;
  bool _didReportFraud = false;
  bool _isLaunchingUninstall = false;

  @override
  void initState() {
    super.initState();
    _pulse = AnimationController(
      duration: const Duration(milliseconds: 800),
      vsync: this,
    )..repeat(reverse: true);
    _pulseAnim = Tween<double>(
      begin: 0.6,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _pulse, curve: Curves.easeInOut));
    WidgetsBinding.instance.addPostFrameCallback((_) => _reportThreatOnce());
  }

  @override
  void dispose() {
    _pulse.dispose();
    super.dispose();
  }

  void _reportThreatOnce() {
    if (_didReportFraud) {
      return;
    }

    final badPackage = _threatPackageName(widget.result);
    final threatType = _threatType(widget.result);
    if (badPackage.isEmpty || threatType.isEmpty) {
      return;
    }

    _didReportFraud = true;
    unawaited(reportFraudSilently(badPackage, threatType));
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
    if (verdict.startsWith('TROJAN_DETECTED_')) {
      return 'TROJAN_DETECTED';
    }
    return verdict;
  }

  Future<void> _uninstallThreat(String packageName) async {
    if (_isLaunchingUninstall || packageName.isEmpty) {
      return;
    }

    setState(() => _isLaunchingUninstall = true);
    try {
      await _bridge.uninstallApp(packageName);
    } catch (_) {
      // Keep the overlay stable if the Android uninstaller cannot be opened.
    } finally {
      if (mounted) {
        setState(() => _isLaunchingUninstall = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final r = widget.result;
    final verdict = r['verdict'] as String? ?? '';
    final trojanApp =
        verdict.startsWith('TROJAN_DETECTED_')
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
        builder:
            (_, __) => Container(
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
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 28,
                    vertical: 20,
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      // ── Warning icon with glow ──
                      AnimatedBuilder(
                        animation: _pulseAnim,
                        builder:
                            (_, __) => Container(
                              width: 100,
                              height: 100,
                              decoration: BoxDecoration(
                                shape: BoxShape.circle,
                                color: Colors.red.withOpacity(0.2),
                                boxShadow: [
                                  BoxShadow(
                                    color: const Color(
                                      0xFFFF4D4D,
                                    ).withOpacity(0.4 * _pulseAnim.value),
                                    blurRadius: 40,
                                    spreadRadius: 10,
                                  ),
                                ],
                              ),
                              child: Icon(
                                widget.icon,
                                color: Colors.white,
                                size: 56,
                              ),
                            ),
                      ),
                      const SizedBox(height: 28),

                      // ── Title ──
                      Text(
                        widget.title,
                        style: GoogleFonts.orbitron(
                          color: Colors.white,
                          fontSize: 26,
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

                      // ── Hash details box (only for INVALID_SIGNATURE) ──
                      if (verdict == 'INVALID_SIGNATURE' &&
                          liveHash != null &&
                          expectedHash != null)
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(14),
                            color: Colors.black.withOpacity(0.3),
                            border: Border.all(
                              color: Colors.white.withOpacity(0.15),
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              _detailRow(
                                'PACKAGE',
                                r['packageName']?.toString() ?? '',
                              ),
                              const SizedBox(height: 8),
                              _detailRow('VERDICT', 'SIGNATURE MISMATCH'),
                              const Divider(color: Colors.white24, height: 24),
                              _hashDetail('LIVE SHA-256', liveHash),
                              const SizedBox(height: 8),
                              _hashDetail('EXPECTED', expectedHash),
                            ],
                          ),
                        ),

                      // ── Root details box (only for ROOTED_DEVICE) ──
                      if (verdict == 'ROOTED_DEVICE')
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(14),
                            color: Colors.black.withOpacity(0.3),
                            border: Border.all(
                              color: Colors.white.withOpacity(0.15),
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              _detailRow('STATUS', 'ROOT DETECTED'),
                              const SizedBox(height: 8),
                              _detailRow(
                                'RESOLUTION',
                                'Restore device to factory state',
                              ),
                              const SizedBox(height: 8),
                              _detailRow('OPERATIONS', 'LOCKED'),
                            ],
                          ),
                        ),

                      if (trojanApp != null && trojanApp.isNotEmpty)
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(14),
                            color: Colors.black.withOpacity(0.3),
                            border: Border.all(
                              color: Colors.white.withOpacity(0.15),
                            ),
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

                      const SizedBox(height: 28),

                      // ── UNINSTALL THREAT NOW button ──
                      if (canUninstallThreat)
                        Padding(
                          padding: const EdgeInsets.only(bottom: 14),
                          child: GestureDetector(
                            onTap:
                                _isLaunchingUninstall
                                    ? null
                                    : () => _uninstallThreat(uninstallPackage),
                            child: AnimatedBuilder(
                              animation: _pulseAnim,
                              builder:
                                  (_, __) => Container(
                                    width: double.infinity,
                                    padding: const EdgeInsets.symmetric(
                                      vertical: 18,
                                    ),
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
                                          color: const Color(
                                            0xFFFF4D4D,
                                          ).withOpacity(
                                            0.5 * _pulseAnim.value,
                                          ),
                                          blurRadius: 20,
                                          spreadRadius: 2,
                                          offset: const Offset(0, 4),
                                        ),
                                      ],
                                    ),
                                    child: Row(
                                      mainAxisAlignment:
                                          MainAxisAlignment.center,
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
                                          const Icon(
                                            Icons.delete_forever_rounded,
                                            color: Colors.white,
                                            size: 22,
                                          ),
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
                        ),

                      // ── Dismiss button ──
                      GestureDetector(
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
                              Icon(
                                Icons.close_rounded,
                                color: Color(0xFFCC0000),
                                size: 20,
                              ),
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
                      ),
                    ],
                  ),
                ),
              ),
            ),
      ),
    );
  }

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
}
