// ============================================================================
// YONO SHIELD — main.dart (v6 — Modular Architecture)
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
//   │    ├─ ScamGamePage → Gamified Scam Simulator        │
//   │    └─ RedAlertOverlay (Audio-Visual red modal + TTS)│
//   │              │                                      │
//   │       MethodChannel                                 │
//   │              │                                      │
//   │  Kotlin Native (MainActivity.kt)                    │
//   │    ├─ isDeviceRooted()          → root detection    │
//   │    ├─ scanForTrojans()          → overlay trojans   │
//   │    ├─ getAppSignatureHash(pkg)  → SHA-256           │
//   │    ├─ verifyAppSecurity(pkg)    → 4-gate pipeline   │
//   │    ├─ checkRogueAccessibility   → Loophole 4        │
//   │    ├─ checkRogueNotifListeners  → Loophole 7        │
//   │    ├─ DeviceIntegrity           → Loophole 8        │
//   │    └─ FLAG_SECURE               → anti-tapjacking   │
//   └─────────────────────────────────────────────────────┘
// ============================================================================

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_windowmanager/flutter_windowmanager.dart';
import 'package:google_fonts/google_fonts.dart';
import 'pages/clone_radar_page.dart';
import 'pages/sms_interceptor_page.dart';
import 'pages/overlay_control_page.dart';
import 'pages/scam_game_page.dart';
import 'services/accessibility_scanner.dart';
import 'services/device_integrity.dart';
import 'services/notification_scanner.dart';
import 'services/sync_manager.dart' as sync_manager;
import 'widgets/red_alert_overlay.dart';

Future<void> reportFraudSilently(String badPackage, String threatType) async {
  // ── KAVACH Telemetry Bridge ──
  // For Android Emulator → host machine: http://10.0.2.2:8080/api/telemetry
  // For Ngrok tunnel (demo): https://YOUR_NGROK_ID.ngrok-free.app/api/telemetry
  await sync_manager.reportFraudSilently(badPackage, threatType);

  /*
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
  */
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // ── Anti-Tapjacking: FLAG_SECURE ──
  // This single line instructs the Android OS to block ALL
  // SYSTEM_ALERT_WINDOW overlays and screen recorders from capturing
  // the KAVACH interface. It neutralizes invisible overlay attacks
  // (tapjacking) and prevents screen recording / screenshots of
  // sensitive banking data. No malicious app can draw on top of us.
  await FlutterWindowManager.addFlags(FlutterWindowManager.FLAG_SECURE);

  await sync_manager.SyncManager.instance.initialize();
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
    with TickerProviderStateMixin, WidgetsBindingObserver {
  final AccessibilityScanner _accessibilityScanner = AccessibilityScanner();
  final NotificationScanner _notificationScanner = NotificationScanner();
  final DeviceIntegrity _deviceIntegrity = DeviceIntegrity();

  int _tab = 0;
  late PageController _pageCtrl;
  late AnimationController _shieldPulse;
  late Animation<double> _glow;
  bool _isSecurityScanInFlight = false;
  bool _isThreatAlertOpen = false;
  bool _isDeviceCompromised = false;
  String _compromiseReason = '';

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _pageCtrl = PageController();
    _shieldPulse = AnimationController(
      duration: const Duration(seconds: 3),
      vsync: this,
    )..repeat(reverse: true);
    _glow = Tween<double>(
      begin: 0.4,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _shieldPulse, curve: Curves.easeInOut));
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // ── GATE 0: Device Integrity (Root/Jailbreak) ──
      // Must run FIRST, before any other security check.
      // If the device is compromised, show a permanent black screen
      // and suspend ALL banking operations.
      unawaited(_checkDeviceIntegrity());
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _pageCtrl.dispose();
    _shieldPulse.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      // Re-check device integrity on every resume (user may have rooted
      // while the app was in background).
      unawaited(_checkDeviceIntegrity());
    }
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
  // Delegates to the standalone RedAlertOverlay widget.
  void _showThreatAlert(Map<String, dynamic> result) {
    unawaited(_showThreatAlertAsync(result));
  }

  Future<void> _showThreatAlertAsync(Map<String, dynamic> result) async {
    if (!mounted || _isThreatAlertOpen) {
      return;
    }

    _isThreatAlertOpen = true;
    try {
      await showRedAlertOverlay(context, result);
    } finally {
      _isThreatAlertOpen = false;
    }
  }

  // ── GATE 0: Device Integrity Check (Root/Jailbreak) ──
  // If the device is compromised, render a permanent black screen.
  // This cannot be dismissed — banking is fully suspended.
  Future<void> _checkDeviceIntegrity() async {
    if (!mounted || _isDeviceCompromised) return;

    try {
      final result = await _deviceIntegrity.verifyDeviceIntegrity();
      if (!mounted) return;

      if (!result.isIntact) {
        setState(() {
          _isDeviceCompromised = true;
          _compromiseReason = result.failureReason ?? 'Unknown compromise';
        });

        // Log to telemetry
        unawaited(
          reportFraudSilently('DEVICE_OS', 'ROOTED_DEVICE'),
        );
        return;
      }
    } catch (error) {
      debugPrint('Device integrity check failed: \$error');
    }

    // Device is clean — proceed to runtime security scans
    unawaited(_runSecurityScansOnResume());
  }

  // ── Runtime Security Scans (Accessibility + Notifications) ──
  // Runs both loophole checks sequentially on every app resume.
  Future<void> _runSecurityScansOnResume() async {
    if (!mounted || _isSecurityScanInFlight || _isThreatAlertOpen) {
      return;
    }

    _isSecurityScanInFlight = true;
    try {
      // ── Loophole 4: Accessibility Service Hijack ──
      await _scanAccessibilityOnResume();

      // ── Loophole 7: Notification Snooping ──
      if (mounted && !_isThreatAlertOpen) {
        await _scanNotificationListenersOnResume();
      }
    } finally {
      _isSecurityScanInFlight = false;
    }
  }

  Future<void> _scanAccessibilityOnResume() async {
    if (!mounted || _isThreatAlertOpen) return;

    try {
      final scanResult = await _accessibilityScanner.scanForHijack();
      if (!mounted || !scanResult.isThreat) return;

      final packageName = scanResult.packageName?.trim() ?? '';
      final appName =
          scanResult.appName?.trim().isNotEmpty == true
              ? scanResult.appName!.trim()
              : packageName.isNotEmpty
              ? packageName
              : 'Unknown app';
      final installer = scanResult.installer ?? 'UNKNOWN';

      // Log every rogue service to the SQLite Telemetry Vault
      for (final rogue in scanResult.rogueServices) {
        unawaited(
          reportFraudSilently(
            rogue.packageName,
            'ROGUE_ACCESSIBILITY_SERVICE',
          ),
        );
      }

      await _showThreatAlertAsync({
        'verdict': 'ROGUE_ACCESSIBILITY_SERVICE',
        'packageName': packageName,
        'appName': appName,
        'serviceName': scanResult.serviceName,
        'installer': installer,
        'rogueCount': scanResult.rogueServices.length,
        'isRooted': false,
        'trojanApp': null,
        'liveHash': null,
        'expectedHash': 'UNAVAILABLE',
        'message':
            "'\$appName' was sideloaded (installer: \$installer) and is using "
            "Android accessibility access to monitor or control your screen. "
            "Disable or uninstall it immediately before using YONO.",
      });
    } catch (error) {
      debugPrint('Accessibility resume scan failed: \$error');
    }
  }

  // ── Loophole 7: Notification Snooper Detection ──
  Future<void> _scanNotificationListenersOnResume() async {
    if (!mounted || _isThreatAlertOpen) return;

    try {
      final scanResult = await _notificationScanner.scanForSnoopers();
      if (!mounted || !scanResult.isThreat) return;

      final packageName = scanResult.packageName?.trim() ?? '';
      final appName =
          scanResult.appName?.trim().isNotEmpty == true
              ? scanResult.appName!.trim()
              : packageName.isNotEmpty
              ? packageName
              : 'Unknown app';
      final installer = scanResult.installer ?? 'UNKNOWN';

      // Log every rogue listener to telemetry
      for (final rogue in scanResult.rogueListeners) {
        unawaited(
          reportFraudSilently(
            rogue.packageName,
            'ROGUE_NOTIFICATION_LISTENER',
          ),
        );
      }

      await _showThreatAlertAsync({
        'verdict': 'ROGUE_NOTIFICATION_LISTENER',
        'packageName': packageName,
        'appName': appName,
        'installer': installer,
        'rogueCount': scanResult.rogueListeners.length,
        'isRooted': false,
        'trojanApp': null,
        'liveHash': null,
        'expectedHash': 'UNAVAILABLE',
        'message':
            "'\$appName' was sideloaded (installer: \$installer) and has "
            "notification access, which means it can read your OTPs, "
            "banking alerts, and personal messages. "
            "Revoke its access or uninstall it immediately.",
      });
    } catch (error) {
      debugPrint('Notification listener scan failed: \$error');
    }
  }

  @override
  Widget build(BuildContext context) {
    // ── GATE 0: Permanent lockout if device is rooted/jailbroken ──
    if (_isDeviceCompromised) {
      return _buildCompromisedScreen();
    }

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
                const ScamGamePage(),
              ],
            ),
          ),
        ],
      ),
      bottomNavigationBar: _bottomNav(),
    );
  }

  // ── Permanent Black Screen — Root/Jailbreak Detected ──
  Widget _buildCompromisedScreen() {
    return Scaffold(
      backgroundColor: Colors.black,
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Pulsing red shield icon
                Container(
                  width: 120,
                  height: 120,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: const Color(0xFFCC0000).withOpacity(0.15),
                    border: Border.all(
                      color: const Color(0xFFCC0000).withOpacity(0.5),
                      width: 3,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFFCC0000).withOpacity(0.3),
                        blurRadius: 40,
                        spreadRadius: 10,
                      ),
                    ],
                  ),
                  child: const Icon(
                    Icons.phonelink_lock_rounded,
                    color: Color(0xFFFF4D4D),
                    size: 60,
                  ),
                ),
                const SizedBox(height: 32),

                // Title
                Text(
                  '🚨 KAVACH',
                  style: GoogleFonts.orbitron(
                    color: const Color(0xFFFF4D4D),
                    fontSize: 28,
                    fontWeight: FontWeight.w900,
                    letterSpacing: 4,
                  ),
                ),
                const SizedBox(height: 16),

                // Subtitle badge
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 8,
                  ),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(8),
                    color: const Color(0xFFCC0000).withOpacity(0.2),
                    border: Border.all(
                      color: const Color(0xFFCC0000).withOpacity(0.4),
                    ),
                  ),
                  child: Text(
                    'DEVICE INTEGRITY COMPROMISED',
                    style: GoogleFonts.orbitron(
                      color: const Color(0xFFFF4D4D),
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 2,
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Message
                Text(
                  'Root / Jailbreak detected.\n\n'
                  'Banking operations are SUSPENDED.\n\n'
                  'This device\'s operating system has been modified, '
                  'allowing malicious actors to bypass OS-level security '
                  'controls, intercept banking transactions, and '
                  'capture credentials.\n\n'
                  'Please restore this device to factory settings '
                  'before using YONO.',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.7),
                    fontSize: 14,
                    height: 1.6,
                  ),
                ),
                const SizedBox(height: 32),

                // Technical detail
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    color: Colors.white.withOpacity(0.05),
                    border: Border.all(
                      color: Colors.white.withOpacity(0.1),
                    ),
                  ),
                  child: Text(
                    _compromiseReason,
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: Colors.white.withOpacity(0.4),
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
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
                  'SCAM SIMULATOR • LEARN TO STAY SAFE',
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
            _navItem(3, Icons.school_rounded, 'LEARN'),
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
