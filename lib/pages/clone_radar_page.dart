// ============================================================================
// YONO SHIELD — Radar Page (v4 — Trojan Overlay Detection)
// ============================================================================
//
// The "RADAR" tab implements the full security pipeline:
//   1. User presses "SCAN NOW"
//   2. Invokes verifyAppSecurity("com.sbi.fakeyono") via MethodChannel
//   3. Handles the verdict logic tree:
//      - "SAFE"                    → Green success card
//      - "ROOTED_DEVICE"           → Red alert overlay (OS compromised)
//      - "TROJAN_DETECTED_{name}"  → Red alert overlay (trojan overlay app)
//      - "INVALID_SIGNATURE"       → Red alert overlay (brand impersonation)
//      - "APP_NOT_FOUND"           → Amber info card
//
// ============================================================================
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/security_bridge.dart';
import '../widgets/scan_animation.dart';

class RadarPage extends StatefulWidget {
  /// Callback to trigger the full-screen threat alert from the parent scaffold
  final void Function(Map<String, dynamic> result) onThreatDetected;
  const RadarPage({super.key, required this.onThreatDetected});

  @override
  State<RadarPage> createState() => _RadarPageState();
}

class _RadarPageState extends State<RadarPage>
    with AutomaticKeepAliveClientMixin, TickerProviderStateMixin {
  final SecurityBridge _bridge = SecurityBridge();

  bool _isScanning = false;
  bool _hasScanned = false;
  Map<String, dynamic>? _securityResult;
  String? _error;

  // The mock package name we're verifying via the Cryptographic Gatekeeper
  static const String _targetPackage = 'com.sbi.fakeyono';

  // Animation controllers
  late AnimationController _resultFadeCtrl;
  late Animation<double> _resultFade;
  late AnimationController _successPulseCtrl;
  late Animation<double> _successPulse;

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();
    _resultFadeCtrl = AnimationController(
      duration: const Duration(milliseconds: 600),
      vsync: this,
    );
    _resultFade = CurvedAnimation(parent: _resultFadeCtrl, curve: Curves.easeOut);

    _successPulseCtrl = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    );
    _successPulse = Tween<double>(begin: 0.6, end: 1.0).animate(
      CurvedAnimation(parent: _successPulseCtrl, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _resultFadeCtrl.dispose();
    _successPulseCtrl.dispose();
    super.dispose();
  }

  // ==========================================================================
  // SCAN — Invoke the Cryptographic Gatekeeper
  // ==========================================================================
  Future<void> _scan() async {
    setState(() {
      _isScanning = true;
      _error = null;
      _securityResult = null;
      _hasScanned = false;
    });
    _resultFadeCtrl.reset();
    _successPulseCtrl.stop();

    try {
      // Small delay for dramatic scanning effect
      await Future.delayed(const Duration(milliseconds: 1500));

      // Invoke the master verifyAppSecurity via MethodChannel → Kotlin
      final result = await _bridge.verifyAppSecurity(_targetPackage);

      setState(() {
        _securityResult = result;
        _isScanning = false;
        _hasScanned = true;
      });

      // Animate result card in
      _resultFadeCtrl.forward();

      // Handle the verdict logic tree
      final verdict = result['verdict'] as String? ?? '';

      if (verdict == 'SAFE') {
        // Green success — start gentle pulse
        _successPulseCtrl.repeat(reverse: true);
      } else if (verdict == 'ROOTED_DEVICE') {
        // CRITICAL: Device OS is compromised
        await Future.delayed(const Duration(milliseconds: 400));
        widget.onThreatDetected(result);
      } else if (verdict.startsWith('TROJAN_DETECTED_')) {
        // CRITICAL: Trojan overlay app found
        await Future.delayed(const Duration(milliseconds: 400));
        widget.onThreatDetected(result);
      } else if (verdict == 'INVALID_SIGNATURE') {
        // THREAT: Brand impersonation detected
        await Future.delayed(const Duration(milliseconds: 400));
        widget.onThreatDetected(result);
      }
      // APP_NOT_FOUND is handled inline (amber card)
    } catch (e) {
      setState(() {
        _isScanning = false;
        _error = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return CustomScrollView(
      physics: const BouncingScrollPhysics(),
      slivers: [
        // ── Radar Animation + Header ──
        SliverToBoxAdapter(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 24, 16, 8),
            child: Column(children: [
              ScanAnimation(isScanning: _isScanning, size: 160),
              const SizedBox(height: 20),
              Text(
                _isScanning
                    ? 'VERIFYING SECURITY...'
                    : _hasScanned
                        ? 'GATEKEEPER VERDICT'
                        : 'CRYPTOGRAPHIC GATEKEEPER',
                style: GoogleFonts.orbitron(
                  color: const Color(0xFF00FFA3).withOpacity(0.9),
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 3,
                ),
              ),
              const SizedBox(height: 6),
              Text(
                _isScanning
                    ? 'Root detection → Trojan scan → Cert extraction → Hash compare...'
                    : 'Root + Trojan + SHA-256 Signature Verification',
                style: TextStyle(
                    color: Colors.white.withOpacity(0.45), fontSize: 12),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              // Target package indicator
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(20),
                  color: Colors.white.withOpacity(0.05),
                  border: Border.all(color: Colors.white.withOpacity(0.1)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.apps_rounded,
                        color: Colors.white.withOpacity(0.4), size: 14),
                    const SizedBox(width: 6),
                    Text(
                      'TARGET: $_targetPackage',
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.4),
                        fontSize: 10,
                        fontFamily: 'monospace',
                        fontWeight: FontWeight.w600,
                        letterSpacing: 0.5,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // Scan button or progress
              if (!_isScanning) _buildScanButton(),
              if (_isScanning) _buildScanProgress(),
              if (_error != null) _buildError(),
            ]),
          ),
        ),

        // ── Gatekeeper Pipeline Status ──
        if (_hasScanned && _securityResult != null)
          SliverToBoxAdapter(child: _buildPipelineStatus()),

        // ── Result Card ──
        if (_hasScanned && _securityResult != null)
          SliverToBoxAdapter(
            child: FadeTransition(
              opacity: _resultFade,
              child: _buildResultCard(),
            ),
          ),

        const SliverToBoxAdapter(child: SizedBox(height: 100)),
      ],
    );
  }

  // ==========================================================================
  // SCAN BUTTON
  // ==========================================================================
  Widget _buildScanButton() => GestureDetector(
        onTap: _scan,
        child: Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(vertical: 16),
          margin: const EdgeInsets.symmetric(horizontal: 20),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            gradient: const LinearGradient(
                colors: [Color(0xFF00FFA3), Color(0xFF00D4FF)]),
            boxShadow: [
              BoxShadow(
                  color: const Color(0xFF00FFA3).withOpacity(0.3),
                  blurRadius: 16,
                  offset: const Offset(0, 4)),
            ],
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.security_rounded,
                  color: Color(0xFF0B101E), size: 24),
              const SizedBox(width: 10),
              Text(
                _hasScanned ? 'RESCAN SECURITY' : 'SCAN NOW',
                style: GoogleFonts.orbitron(
                  color: const Color(0xFF0B101E),
                  fontSize: 14,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 2,
                ),
              ),
            ],
          ),
        ),
      );

  // ==========================================================================
  // SCAN PROGRESS
  // ==========================================================================
  Widget _buildScanProgress() => Padding(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 20),
        child: Column(children: [
          ClipRRect(
            borderRadius: BorderRadius.circular(8),
            child: const LinearProgressIndicator(
              backgroundColor: Color(0xFF1A2035),
              valueColor:
                  AlwaysStoppedAnimation<Color>(Color(0xFF00FFA3)),
              minHeight: 4,
            ),
          ),
          const SizedBox(height: 12),
          _buildGateIndicator('GATE 1', 'Root Detection', true),
          const SizedBox(height: 6),
          _buildGateIndicator('GATE 2', 'Trojan Overlay Scan', true),
          const SizedBox(height: 6),
          _buildGateIndicator('GATE 3', 'Certificate Extraction', true),
          const SizedBox(height: 6),
          _buildGateIndicator('GATE 4', 'Hash Comparison', true),
        ]),
      );

  Widget _buildGateIndicator(String gate, String label, bool active) => Row(
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: active
                  ? const Color(0xFF00FFA3).withOpacity(0.6)
                  : Colors.white.withOpacity(0.2),
            ),
          ),
          const SizedBox(width: 8),
          Text(gate,
              style: GoogleFonts.orbitron(
                color: const Color(0xFF00FFA3).withOpacity(0.6),
                fontSize: 9,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
              )),
          const SizedBox(width: 8),
          Text(label,
              style: TextStyle(
                  color: Colors.white.withOpacity(0.35),
                  fontSize: 11)),
        ],
      );

  // ==========================================================================
  // ERROR DISPLAY
  // ==========================================================================
  Widget _buildError() => Container(
        margin: const EdgeInsets.only(top: 12),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          color: Colors.red.withOpacity(0.1),
          border: Border.all(color: Colors.red.withOpacity(0.3)),
        ),
        child: Row(children: [
          const Icon(Icons.error_outline_rounded,
              color: Colors.red, size: 18),
          const SizedBox(width: 8),
          Expanded(
            child: Text(_error!,
                style:
                    const TextStyle(color: Colors.redAccent, fontSize: 12)),
          ),
        ]),
      );

  // ==========================================================================
  // PIPELINE STATUS — Shows gate pass/fail indicators after scan
  // ==========================================================================
  Widget _buildPipelineStatus() {
    final verdict = _securityResult!['verdict'] as String? ?? '';
    final isRooted = _securityResult!['isRooted'] as bool? ?? false;
    final isTrojan = verdict.startsWith('TROJAN_DETECTED_');

    // Determine gate statuses
    final gate1Pass = !isRooted;
    final gate2Pass = !isTrojan && gate1Pass;
    final gate3Pass = verdict != 'APP_NOT_FOUND' && gate2Pass;
    final gate4Pass = verdict == 'SAFE';

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(16),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
          child: Container(
            padding:
                const EdgeInsets.symmetric(horizontal: 8, vertical: 14),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(16),
              color: Colors.white.withOpacity(0.05),
              border: Border.all(color: Colors.white.withOpacity(0.1)),
            ),
            child: Column(
              children: [
                Text('SECURITY PIPELINE',
                    style: GoogleFonts.orbitron(
                      color: Colors.white.withOpacity(0.5),
                      fontSize: 9,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 2,
                    )),
                const SizedBox(height: 12),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    _pipelineGate('ROOT\nDETECT', gate1Pass),
                    _pipelineArrow(gate1Pass),
                    _pipelineGate('TROJAN\nSCAN', gate2Pass),
                    _pipelineArrow(gate2Pass),
                    _pipelineGate('CERT\nEXTRACT', gate3Pass),
                    _pipelineArrow(gate3Pass),
                    _pipelineGate('HASH\nCOMPARE', gate4Pass),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _pipelineGate(String label, bool pass) {
    final color = pass ? const Color(0xFF00FFA3) : const Color(0xFFFF4D4D);
    return Column(children: [
      Container(
        width: 44,
        height: 44,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: color.withOpacity(0.15),
          border: Border.all(color: color.withOpacity(0.5), width: 1.5),
        ),
        child: Icon(
          pass ? Icons.check_rounded : Icons.close_rounded,
          color: color,
          size: 22,
        ),
      ),
      const SizedBox(height: 6),
      Text(label,
          textAlign: TextAlign.center,
          style: TextStyle(
              color: color.withOpacity(0.8),
              fontSize: 8,
              fontWeight: FontWeight.w700,
              letterSpacing: 1,
              height: 1.3)),
    ]);
  }

  Widget _pipelineArrow(bool active) {
    final color = active
        ? const Color(0xFF00FFA3).withOpacity(0.5)
        : const Color(0xFFFF4D4D).withOpacity(0.3);
    return Padding(
      padding: const EdgeInsets.only(bottom: 20),
      child: Icon(Icons.chevron_right_rounded, color: color, size: 20),
    );
  }

  // ==========================================================================
  // RESULT CARD — Renders based on verdict
  // ==========================================================================
  Widget _buildResultCard() {
    final verdict = _securityResult!['verdict'] as String? ?? '';
    final message = _securityResult!['message'] as String? ?? '';
    final liveHash = _securityResult!['liveHash']?.toString() ?? 'N/A';
    final expectedHash =
        _securityResult!['expectedHash']?.toString() ?? 'N/A';
    final packageName =
        _securityResult!['packageName']?.toString() ?? _targetPackage;
    final trojanApp = _securityResult!['trojanApp']?.toString();

    // Handle TROJAN_DETECTED_ prefix
    if (verdict.startsWith('TROJAN_DETECTED_')) {
      final appName = trojanApp ?? verdict.replaceFirst('TROJAN_DETECTED_', '');
      return _buildThreatCard(
        icon: Icons.pest_control_rounded,
        title: 'TROJAN DETECTED',
        subtitle: 'MALICIOUS OVERLAY APP',
        message: message,
        color: const Color(0xFFFF4D4D),
        packageName: packageName,
        liveHash: liveHash,
        expectedHash: expectedHash,
        extraDetail: appName,
      );
    }

    switch (verdict) {
      case 'SAFE':
        return _buildSafeCard(message, liveHash, expectedHash, packageName);
      case 'ROOTED_DEVICE':
        return _buildThreatCard(
          icon: Icons.phonelink_lock_rounded,
          title: 'DEVICE COMPROMISED',
          subtitle: 'ROOT DETECTED',
          message: message,
          color: const Color(0xFFFF4D4D),
          packageName: packageName,
          liveHash: liveHash,
          expectedHash: expectedHash,
        );
      case 'INVALID_SIGNATURE':
        return _buildThreatCard(
          icon: Icons.gpp_bad_rounded,
          title: 'BRAND IMPERSONATION',
          subtitle: 'INVALID SIGNATURE',
          message: message,
          color: const Color(0xFFFF4D4D),
          packageName: packageName,
          liveHash: liveHash,
          expectedHash: expectedHash,
        );
      case 'APP_NOT_FOUND':
        return _buildInfoCard(message, packageName);
      default:
        return _buildInfoCard(
            'Unknown verdict: $verdict', packageName);
    }
  }

  // ── GREEN: Safe / Verified ────────────────────────────────────────────────
  Widget _buildSafeCard(
      String message, String liveHash, String expectedHash, String pkg) {
    const accent = Color(0xFF00FFA3);
    return AnimatedBuilder(
      animation: _successPulse,
      builder: (_, __) => Container(
        margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(20),
          child: BackdropFilter(
            filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
            child: Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color:
                      accent.withOpacity(0.3 * _successPulse.value),
                  width: 1.5,
                ),
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    accent
                        .withOpacity(0.12 * _successPulse.value),
                    accent.withOpacity(0.04),
                  ],
                ),
              ),
              child: Column(children: [
                // Shield icon with glow
                Container(
                  width: 72,
                  height: 72,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: accent.withOpacity(0.15),
                    boxShadow: [
                      BoxShadow(
                        color: accent.withOpacity(
                            0.25 * _successPulse.value),
                        blurRadius: 24,
                        spreadRadius: 4,
                      ),
                    ],
                  ),
                  child: const Icon(Icons.verified_user_rounded,
                      color: accent, size: 36),
                ),
                const SizedBox(height: 16),
                Text('SYSTEM VERIFIED',
                    style: GoogleFonts.orbitron(
                      color: accent,
                      fontSize: 18,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 3,
                    )),
                const SizedBox(height: 6),
                Text('Environment Secure',
                    style: TextStyle(
                        color: accent.withOpacity(0.7),
                        fontSize: 13,
                        fontWeight: FontWeight.w500)),
                const SizedBox(height: 16),
                // Details
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    color: Colors.black.withOpacity(0.25),
                    border: Border.all(
                        color: accent.withOpacity(0.15)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _resultDetailRow(
                          'PACKAGE', pkg, accent),
                      const SizedBox(height: 6),
                      _resultDetailRow(
                          'ROOT STATUS', '✓ Clean', accent),
                      const SizedBox(height: 6),
                      _resultDetailRow(
                          'SIGNATURE', '✓ Verified', accent),
                      Divider(
                          color: accent.withOpacity(0.15),
                          height: 20),
                      _hashDetail('SHA-256', liveHash, accent),
                    ],
                  ),
                ),
              ]),
            ),
          ),
        ),
      ),
    );
  }

  // ── RED: Threat Detected ──────────────────────────────────────────────────
  Widget _buildThreatCard({
    required IconData icon,
    required String title,
    required String subtitle,
    required String message,
    required Color color,
    required String packageName,
    required String liveHash,
    required String expectedHash,
    String? extraDetail,
  }) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(20),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
          child: Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: color.withOpacity(0.4), width: 1.5),
              gradient: LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  color.withOpacity(0.15),
                  color.withOpacity(0.05),
                ],
              ),
            ),
            child: Column(children: [
              Container(
                width: 72,
                height: 72,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: color.withOpacity(0.2),
                  boxShadow: [
                    BoxShadow(
                      color: color.withOpacity(0.3),
                      blurRadius: 24,
                      spreadRadius: 4,
                    ),
                  ],
                ),
                child: Icon(icon, color: color, size: 36),
              ),
              const SizedBox(height: 16),
              Text(title,
                  style: GoogleFonts.orbitron(
                    color: color,
                    fontSize: 16,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 2,
                  )),
              const SizedBox(height: 6),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(20),
                  color: color.withOpacity(0.2),
                ),
                child: Text(subtitle,
                    style: TextStyle(
                        color: color,
                        fontSize: 10,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.5)),
              ),
              const SizedBox(height: 12),
              Text(message,
                  textAlign: TextAlign.center,
                  style: TextStyle(
                      color: Colors.white.withOpacity(0.7),
                      fontSize: 12,
                      height: 1.5)),
              const SizedBox(height: 16),
              // Details
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(12),
                  color: Colors.black.withOpacity(0.3),
                  border: Border.all(color: color.withOpacity(0.2)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _resultDetailRow('PACKAGE', packageName, color),
                    const SizedBox(height: 6),
                    _resultDetailRow('VERDICT', subtitle, color),
                    if (extraDetail != null) ...[
                      const SizedBox(height: 6),
                      _resultDetailRow('TROJAN APP', extraDetail, color),
                    ],
                    if (liveHash != 'N/A' && liveHash != 'null') ...[
                      Divider(color: color.withOpacity(0.15), height: 20),
                      _hashDetail('LIVE HASH', liveHash, color),
                      const SizedBox(height: 6),
                      _hashDetail('EXPECTED', expectedHash, color),
                    ],
                  ],
                ),
              ),
            ]),
          ),
        ),
      ),
    );
  }

  // ── AMBER: Info / App Not Found ───────────────────────────────────────────
  Widget _buildInfoCard(String message, String packageName) {
    const color = Color(0xFFFF9F1C);
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(20),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
          child: Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: color.withOpacity(0.3), width: 1.5),
              gradient: LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  color.withOpacity(0.1),
                  color.withOpacity(0.03),
                ],
              ),
            ),
            child: Column(children: [
              Container(
                width: 60,
                height: 60,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: color.withOpacity(0.15),
                ),
                child: const Icon(Icons.search_off_rounded,
                    color: color, size: 30),
              ),
              const SizedBox(height: 14),
              Text('APP NOT FOUND',
                  style: GoogleFonts.orbitron(
                    color: color,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 2,
                  )),
              const SizedBox(height: 8),
              Text(message,
                  textAlign: TextAlign.center,
                  style: TextStyle(
                      color: Colors.white.withOpacity(0.6),
                      fontSize: 12,
                      height: 1.5)),
              const SizedBox(height: 12),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(8),
                  color: Colors.black.withOpacity(0.25),
                  border: Border.all(color: color.withOpacity(0.2)),
                ),
                child: Text(packageName,
                    style: TextStyle(
                        color: color.withOpacity(0.7),
                        fontSize: 11,
                        fontFamily: 'monospace')),
              ),
            ]),
          ),
        ),
      ),
    );
  }

  // ── Shared detail widgets ─────────────────────────────────────────────────
  Widget _resultDetailRow(String label, String value, Color c) => Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 90,
            child: Text(label,
                style: TextStyle(
                    color: c.withOpacity(0.6),
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 1)),
          ),
          Expanded(
            child: Text(value,
                style: const TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                    fontWeight: FontWeight.w500)),
          ),
        ],
      );

  Widget _hashDetail(String label, String hash, Color c) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label,
              style: TextStyle(
                  color: c.withOpacity(0.5),
                  fontSize: 9,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.5)),
          const SizedBox(height: 3),
          Text(hash,
              style: TextStyle(
                  color: Colors.white.withOpacity(0.6),
                  fontSize: 10,
                  fontFamily: 'monospace',
                  height: 1.4),
              maxLines: 3,
              overflow: TextOverflow.ellipsis),
        ],
      );
}
