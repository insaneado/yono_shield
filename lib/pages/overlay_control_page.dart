// ============================================================================
// YONO SHIELD — Overlay Control Page (FULLY WIRED)
// ============================================================================
// Controls the native OverlayService via MethodChannel.
// Features:
//   - Live permission status check (SYSTEM_ALERT_WINDOW)
//   - Grant permission button → opens Android overlay settings
//   - Test Lockdown button → triggers the blocking overlay
//   - Auto re-checks permission when returning from settings
// ============================================================================

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/security_bridge.dart';

class OverlayPage extends StatefulWidget {
  const OverlayPage({super.key});

  @override
  State<OverlayPage> createState() => _OverlayPageState();
}

class _OverlayPageState extends State<OverlayPage> with WidgetsBindingObserver {
  final SecurityBridge _bridge = SecurityBridge();

  bool _hasPermission = false;
  bool _isChecking = true;
  bool _overlayActive = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _checkPermission();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  // Re-check when user returns from Android Settings
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _checkPermission();
    }
  }

  Future<void> _checkPermission() async {
    final granted = await _bridge.checkOverlayPermission();
    if (mounted) {
      setState(() {
        _hasPermission = granted;
        _isChecking = false;
      });
    }
  }

  Future<void> _grantPermission() async {
    await _bridge.requestOverlayPermission();
  }

  Future<void> _toggleOverlay() async {
    if (_overlayActive) {
      await _bridge.hideLockdownOverlay();
      if (mounted) setState(() => _overlayActive = false);
    } else {
      try {
        await _bridge.showLockdownOverlay();
        if (mounted) setState(() => _overlayActive = true);
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Overlay failed: $e'),
              backgroundColor: const Color(0xFFFF4D4D),
            ),
          );
        }
      }
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
          const SizedBox(height: 24),
          _title(),
          const SizedBox(height: 8),
          _subtitle(),
          const SizedBox(height: 28),
          _permissionCard(),
          const SizedBox(height: 16),
          if (_hasPermission) _testOverlayButton(),
          const SizedBox(height: 24),
          _howItWorks(),
        ],
      ),
    );
  }

  // ── Hero icon ──
  Widget _heroIcon() => Container(
        width: 100,
        height: 100,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              (_hasPermission
                      ? const Color(0xFF00FFA3)
                      : const Color(0xFFFF4D4D))
                  .withOpacity(0.2),
              (_hasPermission
                      ? const Color(0xFF00FFA3)
                      : const Color(0xFFFF9F1C))
                  .withOpacity(0.1),
            ],
          ),
          border: Border.all(
            color: (_hasPermission
                    ? const Color(0xFF00FFA3)
                    : const Color(0xFFFF4D4D))
                .withOpacity(0.4),
            width: 2,
          ),
        ),
        child: Icon(
          _hasPermission ? Icons.layers_rounded : Icons.layers_clear_rounded,
          color: _hasPermission
              ? const Color(0xFF00FFA3)
              : const Color(0xFFFF4D4D),
          size: 44,
        ),
      );

  // ── Title ──
  Widget _title() => Text(
        'THREAT SHIELD',
        style: GoogleFonts.orbitron(
          color: Colors.white,
          fontSize: 18,
          fontWeight: FontWeight.w800,
          letterSpacing: 3,
        ),
      );

  // ── Subtitle ──
  Widget _subtitle() => Text(
        'Full-screen blocking overlay that\nprevents interaction with malicious apps.',
        style: TextStyle(
          color: Colors.white.withOpacity(0.5),
          fontSize: 13,
          height: 1.6,
        ),
        textAlign: TextAlign.center,
      );

  // ── Permission status card ──
  Widget _permissionCard() {
    final Color statusColor;
    final String statusLabel;
    final IconData statusIcon;

    if (_isChecking) {
      statusColor = const Color(0xFF00D4FF);
      statusLabel = 'CHECKING…';
      statusIcon = Icons.hourglass_top_rounded;
    } else if (_hasPermission) {
      statusColor = const Color(0xFF00FFA3);
      statusLabel = 'GRANTED';
      statusIcon = Icons.check_circle_rounded;
    } else {
      statusColor = const Color(0xFFFF4D4D);
      statusLabel = 'NOT GRANTED';
      statusIcon = Icons.error_outline_rounded;
    }

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(16),
        color: Colors.white.withOpacity(0.05),
        border: Border.all(color: Colors.white.withOpacity(0.1)),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: statusColor.withOpacity(0.15),
                ),
                child: Icon(Icons.lock_rounded, color: statusColor, size: 22),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'SYSTEM_ALERT_WINDOW',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      'Required to display blocking overlay',
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.5),
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(20),
                  color: statusColor.withOpacity(0.15),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(statusIcon, color: statusColor, size: 14),
                    const SizedBox(width: 4),
                    Text(
                      statusLabel,
                      style: TextStyle(
                        color: statusColor,
                        fontSize: 10,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          // Grant / Open Settings button
          GestureDetector(
            onTap: _grantPermission,
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 14),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(12),
                gradient: _hasPermission
                    ? LinearGradient(colors: [
                        const Color(0xFF00FFA3).withOpacity(0.15),
                        const Color(0xFF00D4FF).withOpacity(0.10),
                      ])
                    : const LinearGradient(
                        colors: [Color(0xFFFF9F1C), Color(0xFFFF6B35)]),
                border: _hasPermission
                    ? Border.all(
                        color: const Color(0xFF00FFA3).withOpacity(0.2))
                    : null,
                boxShadow: _hasPermission
                    ? []
                    : [
                        BoxShadow(
                          color: const Color(0xFFFF9F1C).withOpacity(0.3),
                          blurRadius: 12,
                          offset: const Offset(0, 4),
                        ),
                      ],
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    _hasPermission
                        ? Icons.settings_rounded
                        : Icons.security_rounded,
                    color: _hasPermission
                        ? const Color(0xFF00FFA3)
                        : Colors.white,
                    size: 18,
                  ),
                  const SizedBox(width: 10),
                  Text(
                    _hasPermission
                        ? 'OPEN OVERLAY SETTINGS'
                        : 'GRANT PERMISSION',
                    style: GoogleFonts.orbitron(
                      color: _hasPermission
                          ? const Color(0xFF00FFA3)
                          : Colors.white,
                      fontSize: 11,
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
    );
  }

  // ── Test Overlay Button ──
  Widget _testOverlayButton() => GestureDetector(
        onTap: _toggleOverlay,
        child: Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(vertical: 16),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(14),
            gradient: LinearGradient(
              colors: _overlayActive
                  ? [const Color(0xFF00FFA3), const Color(0xFF00D4FF)]
                  : [const Color(0xFFFF4D4D), const Color(0xFFFF6B00)],
            ),
            boxShadow: [
              BoxShadow(
                color: (_overlayActive
                        ? const Color(0xFF00FFA3)
                        : const Color(0xFFFF4D4D))
                    .withOpacity(0.3),
                blurRadius: 16,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                _overlayActive
                    ? Icons.shield_rounded
                    : Icons.warning_amber_rounded,
                color: _overlayActive
                    ? const Color(0xFF0B101E)
                    : Colors.white,
                size: 22,
              ),
              const SizedBox(width: 10),
              Text(
                _overlayActive
                    ? 'DISMISS LOCKDOWN'
                    : 'TEST LOCKDOWN OVERLAY',
                style: GoogleFonts.orbitron(
                  color: _overlayActive
                      ? const Color(0xFF0B101E)
                      : Colors.white,
                  fontSize: 12,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 1.5,
                ),
              ),
            ],
          ),
        ),
      );

  // ── How It Works card ──
  Widget _howItWorks() => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(16),
          color: Colors.white.withOpacity(0.03),
          border: Border.all(color: Colors.white.withOpacity(0.08)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Icon(Icons.info_outline_rounded,
                  color: const Color(0xFF00D4FF).withOpacity(0.7), size: 18),
              const SizedBox(width: 8),
              Text(
                'HOW IT WORKS',
                style: GoogleFonts.orbitron(
                  color: const Color(0xFF00D4FF).withOpacity(0.9),
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.5,
                ),
              ),
            ]),
            const SizedBox(height: 14),
            _step('1', 'When a tampered app is detected, the overlay activates.'),
            _step('2', 'A full-screen red warning blocks access to the threat.'),
            _step('3', 'User must dismiss to return — preventing data entry.'),
          ],
        ),
      );

  Widget _step(String n, String t) => Padding(
        padding: const EdgeInsets.only(bottom: 10),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Container(
            width: 22,
            height: 22,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: const Color(0xFF00D4FF).withOpacity(0.15),
            ),
            child: Center(
              child: Text(n,
                  style: TextStyle(
                      color: const Color(0xFF00D4FF).withOpacity(0.8),
                      fontSize: 11,
                      fontWeight: FontWeight.w700)),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(t,
                style: TextStyle(
                    color: Colors.white.withOpacity(0.5),
                    fontSize: 12,
                    height: 1.5)),
          ),
        ]),
      );
}
