// ============================================================================
// YONO SHIELD — Scam Simulator (Gamified Education Widget)
// ============================================================================
//
// A standalone, reusable Tinder-style swipe game for scam education.
//
// Features:
//   - Visual scenario cards with large icons (no external images needed)
//   - Swipe Left = SCAM,  Swipe Right = SAFE  (or press the massive buttons)
//   - Green ✓ or Red ✗ overlay on answer with TTS audio explanation
//   - Score counter ("Shield Score: 2/4")
//   - Auto-resets when all cards are exhausted
//   - Extremely high-contrast, designed for rural, low-literacy users
//
// Usage:
//   const ScamGame()   — drops into any widget tree
// ============================================================================

import 'dart:async';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_tts/flutter_tts.dart';
import 'package:appinio_swiper/appinio_swiper.dart';

// ============================================================================
// DATA MODEL
// ============================================================================
class ScamScenario {
  final String title;
  final String description;
  final IconData icon;
  final Color iconColor;
  final Color cardGradientStart;
  final Color cardGradientEnd;
  final bool isScam; // true = should swipe left (SCAM)
  final String correctExplanation;
  final String wrongExplanation;

  /// Optional secondary icon + label shown beneath the main icon for extra
  /// visual context (e.g. a phone icon for a phone-call scenario).
  final IconData? secondaryIcon;
  final String? secondaryLabel;

  const ScamScenario({
    required this.title,
    required this.description,
    required this.icon,
    required this.iconColor,
    required this.cardGradientStart,
    required this.cardGradientEnd,
    required this.isScam,
    required this.correctExplanation,
    required this.wrongExplanation,
    this.secondaryIcon,
    this.secondaryLabel,
  });
}

// ============================================================================
// HARDCODED SCENARIOS — Simple conversational language
// ============================================================================
const List<ScamScenario> _scenarios = [
  // ── Scenario 1: WhatsApp lottery scam ──
  ScamScenario(
    title: 'WhatsApp Lottery Message',
    description:
        'An unknown number sends:\n'
        '"Congratulations! You won 10 lakh rupees!\n'
        'Click this link to claim your prize now."',
    icon: Icons.message_rounded,
    iconColor: Color(0xFF25D366),
    cardGradientStart: Color(0xFF1A2A1A),
    cardGradientEnd: Color(0xFF0D1A0D),
    isScam: true,
    correctExplanation:
        'Good job! This is a scam. Banks and lotteries never send winning '
        'messages on WhatsApp. Never click links from unknown numbers.',
    wrongExplanation:
        'Be careful. This is a scam! No real lottery sends messages on '
        'WhatsApp. Scammers use these links to steal your money and '
        'personal information.',
    secondaryIcon: Icons.link_off_rounded,
    secondaryLabel: 'FAKE LINK',
  ),

  // ── Scenario 2: Official YONO on Play Store ──
  ScamScenario(
    title: 'YONO App from Google Play Store',
    description:
        'The official YONO SBI app shown in the\n'
        'Google Play Store with the verified badge\n'
        'and millions of downloads.',
    icon: Icons.verified_rounded,
    iconColor: Color(0xFF4285F4),
    cardGradientStart: Color(0xFF1A1A2A),
    cardGradientEnd: Color(0xFF0D0D1A),
    isScam: false,
    correctExplanation:
        'Correct! Downloading apps from the official Google Play Store '
        'with a verified badge is safe. Always check the developer name '
        'and download count.',
    wrongExplanation:
        'Actually, this is safe! The official Play Store with a verified '
        'badge is the right place to download apps. Always look for the '
        'blue verification badge.',
    secondaryIcon: Icons.store_rounded,
    secondaryLabel: 'PLAY STORE',
  ),

  // ── Scenario 3: Tampered QR code ──
  ScamScenario(
    title: 'QR Code on Shop Payment Scanner',
    description:
        'A sticker with a QR code is pasted\n'
        'OVER the shop\'s original payment scanner.\n'
        'It looks slightly crooked and new.',
    icon: Icons.qr_code_scanner_rounded,
    iconColor: Color(0xFFFF9F1C),
    cardGradientStart: Color(0xFF2A1A0A),
    cardGradientEnd: Color(0xFF1A0D05),
    isScam: true,
    correctExplanation:
        'Well done! Scammers paste fake QR codes over real ones. The money '
        'goes to the scammer instead of the shop. Always check if the QR '
        'code looks pasted over or tampered.',
    wrongExplanation:
        'Danger! This is a scam. A QR code pasted OVER another one is a '
        'classic trick. The payment goes to the scammer. Always verify the '
        'QR code is original.',
    secondaryIcon: Icons.warning_amber_rounded,
    secondaryLabel: 'TAMPERED',
  ),

  // ── Scenario 4: Fake bank call asking for OTP ──
  ScamScenario(
    title: 'Bank Calling for OTP',
    description:
        'Someone calls you saying:\n'
        '"I am calling from SBI Bank.\n'
        'Please tell me your OTP to verify\n'
        'your account."',
    icon: Icons.phone_in_talk_rounded,
    iconColor: Color(0xFFFF4D4D),
    cardGradientStart: Color(0xFF2A0A0A),
    cardGradientEnd: Color(0xFF1A0505),
    isScam: true,
    correctExplanation:
        'Excellent! Banks NEVER ask for your OTP on the phone. Your OTP is '
        'secret. Never share it with anyone, even if they claim to be from '
        'the bank.',
    wrongExplanation:
        'This is a scam! No bank employee will ever ask for your OTP. '
        'Your OTP is like a key to your money. Never share it with anyone.',
    secondaryIcon: Icons.no_cell_rounded,
    secondaryLabel: 'NEVER SHARE',
  ),
];

// ============================================================================
// SCAM GAME WIDGET — Standalone, drop-in
// ============================================================================
class ScamGame extends StatefulWidget {
  const ScamGame({super.key});

  @override
  State<ScamGame> createState() => _ScamGameState();
}

class _ScamGameState extends State<ScamGame> with TickerProviderStateMixin {
  final FlutterTts _tts = FlutterTts();
  late AppinioSwiperController _swiperCtrl;

  int _score = 0;
  int _totalAnswered = 0;
  bool _gameComplete = false;
  bool _isSpeaking = false;

  // Overlay feedback state
  bool _showFeedback = false;
  bool _feedbackCorrect = false;
  String _feedbackText = '';

  // Animations
  late AnimationController _feedbackAnimCtrl;
  late Animation<double> _feedbackScale;
  late AnimationController _pulseCtrl;
  late Animation<double> _pulse;
  late AnimationController _buttonBounce;
  late Animation<double> _buttonScale;

  Timer? _feedbackDismissTimer;

  @override
  void initState() {
    super.initState();
    _swiperCtrl = AppinioSwiperController();

    _feedbackAnimCtrl = AnimationController(
      duration: const Duration(milliseconds: 400),
      vsync: this,
    );
    _feedbackScale = CurvedAnimation(
      parent: _feedbackAnimCtrl,
      curve: Curves.elasticOut,
    );

    _pulseCtrl = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    )..repeat(reverse: true);
    _pulse = Tween<double>(begin: 0.8, end: 1.0).animate(
      CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut),
    );

    _buttonBounce = AnimationController(
      duration: const Duration(milliseconds: 600),
      vsync: this,
    )..repeat(reverse: true);
    _buttonScale = Tween<double>(begin: 0.95, end: 1.05).animate(
      CurvedAnimation(parent: _buttonBounce, curve: Curves.easeInOut),
    );

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

  @override
  void dispose() {
    _feedbackDismissTimer?.cancel();
    _tts.stop();
    _feedbackAnimCtrl.dispose();
    _pulseCtrl.dispose();
    _buttonBounce.dispose();
    super.dispose();
  }

  void _resetGame() {
    _feedbackDismissTimer?.cancel();
    _tts.stop();
    setState(() {
      _score = 0;
      _totalAnswered = 0;
      _gameComplete = false;
      _showFeedback = false;
      _isSpeaking = false;
    });
    _swiperCtrl = AppinioSwiperController();
  }

  // ── Called when a card is swiped or a button pressed ──
  void _onSwipe(int index, AxisDirection direction) {
    if (index < 0 || index >= _scenarios.length) return;

    final scenario = _scenarios[index];
    final swipedScam = direction == AxisDirection.left;
    final isCorrect = swipedScam == scenario.isScam;

    setState(() {
      _totalAnswered++;
      if (isCorrect) _score++;
      _showFeedback = true;
      _feedbackCorrect = isCorrect;
      _feedbackText =
          isCorrect ? scenario.correctExplanation : scenario.wrongExplanation;
    });

    _feedbackAnimCtrl.forward(from: 0.0);

    // Speak the explanation
    _tts.speak(
      isCorrect ? scenario.correctExplanation : scenario.wrongExplanation,
    );

    // Auto-dismiss feedback after delay
    _feedbackDismissTimer?.cancel();
    _feedbackDismissTimer = Timer(const Duration(seconds: 5), () {
      if (mounted) {
        setState(() => _showFeedback = false);
        if (_totalAnswered >= _scenarios.length) {
          setState(() => _gameComplete = true);
          _speakScore();
        }
      }
    });
  }

  void _onSwipeEnd(
    int previousIndex,
    int targetIndex,
    SwiperActivity activity,
  ) {
    if (activity is Swipe) {
      _onSwipe(previousIndex, activity.direction);
    }
  }

  void _onEnd() {
    // Handled by _onSwipe counter
  }

  Future<void> _speakScore() async {
    await _tts.speak(
      'Game over. Your shield score is $_score out of ${_scenarios.length}. '
      '${_score == _scenarios.length ? "Perfect! You are a scam detection expert!" : "Keep practicing to protect yourself from scams."}',
    );
  }

  // ============================================================================
  // BUILD
  // ============================================================================
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0B101E),
      body: SafeArea(
        child: Stack(
          children: [
            Column(
              children: [
                const SizedBox(height: 16),
                _buildHeader(),
                const SizedBox(height: 8),
                _buildScoreBar(),
                const SizedBox(height: 12),
                _buildInstructions(),
                const SizedBox(height: 12),
                Expanded(
                  child: _gameComplete ? _buildGameComplete() : _buildCardStack(),
                ),
                if (!_gameComplete) _buildActionButtons(),
                const SizedBox(height: 12),
              ],
            ),
            // Feedback overlay
            if (_showFeedback) _buildFeedbackOverlay(),
          ],
        ),
      ),
    );
  }

  // ── HEADER ─────────────────────────────────────────────────────────────────
  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'SCAM SIMULATOR',
                  style: GoogleFonts.orbitron(
                    color: const Color(0xFF00FFA3),
                    fontSize: 16,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 3,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  'Swipe to learn • Protect yourself',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.4),
                    fontSize: 11,
                    letterSpacing: 0.5,
                  ),
                ),
              ],
            ),
          ),
          // Pulsing shield icon
          AnimatedBuilder(
            animation: _pulse,
            builder: (_, __) => Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: RadialGradient(colors: [
                  const Color(0xFF00FFA3).withOpacity(0.2 * _pulse.value),
                  Colors.transparent,
                ]),
              ),
              child: Icon(
                Icons.school_rounded,
                color: Color.lerp(
                  const Color(0xFF00FFA3).withOpacity(0.5),
                  const Color(0xFF00FFA3),
                  _pulse.value,
                ),
                size: 26,
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ── SCORE BAR ──────────────────────────────────────────────────────────────
  Widget _buildScoreBar() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
          color: Colors.white.withOpacity(0.05),
          border: Border.all(color: Colors.white.withOpacity(0.1)),
        ),
        child: Row(
          children: [
            const Icon(
              Icons.shield_rounded,
              color: Color(0xFF00FFA3),
              size: 22,
            ),
            const SizedBox(width: 10),
            Text(
              'SHIELD SCORE',
              style: GoogleFonts.orbitron(
                color: Colors.white.withOpacity(0.6),
                fontSize: 10,
                fontWeight: FontWeight.w700,
                letterSpacing: 2,
              ),
            ),
            const Spacer(),
            // Animated score pill
            AnimatedContainer(
              duration: const Duration(milliseconds: 300),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(20),
                gradient: LinearGradient(
                  colors: _score > 0
                      ? [const Color(0xFF00FFA3), const Color(0xFF00D4FF)]
                      : [
                          Colors.white.withOpacity(0.1),
                          Colors.white.withOpacity(0.05),
                        ],
                ),
                boxShadow: _score > 0
                    ? [
                        BoxShadow(
                          color: const Color(0xFF00FFA3).withOpacity(0.3),
                          blurRadius: 8,
                          spreadRadius: 1,
                        ),
                      ]
                    : [],
              ),
              child: Text(
                '$_score / ${_scenarios.length}',
                style: GoogleFonts.orbitron(
                  color: _score > 0
                      ? const Color(0xFF0B101E)
                      : Colors.white.withOpacity(0.5),
                  fontSize: 14,
                  fontWeight: FontWeight.w900,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── INSTRUCTIONS ───────────────────────────────────────────────────────────
  Widget _buildInstructions() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          _instructionChip(
            Icons.arrow_back_rounded,
            'SCAM',
            const Color(0xFFFF4D4D),
          ),
          const SizedBox(width: 16),
          Text(
            '← SWIPE →',
            style: TextStyle(
              color: Colors.white.withOpacity(0.3),
              fontSize: 11,
              fontWeight: FontWeight.w700,
              letterSpacing: 1,
            ),
          ),
          const SizedBox(width: 16),
          _instructionChip(
            Icons.arrow_forward_rounded,
            'SAFE',
            const Color(0xFF00FFA3),
          ),
        ],
      ),
    );
  }

  Widget _instructionChip(IconData icon, String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(20),
        color: color.withOpacity(0.1),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, color: color, size: 14),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              color: color,
              fontSize: 10,
              fontWeight: FontWeight.w800,
              letterSpacing: 1,
            ),
          ),
        ],
      ),
    );
  }

  // ── CARD STACK ─────────────────────────────────────────────────────────────
  Widget _buildCardStack() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20),
      child: AppinioSwiper(
        controller: _swiperCtrl,
        cardCount: _scenarios.length,
        cardBuilder: (context, index) =>
            _buildScenarioCard(_scenarios[index], index),
        onSwipeEnd: _onSwipeEnd,
        onEnd: _onEnd,
        swipeOptions: const SwipeOptions.symmetric(
          horizontal: true,
          vertical: false,
        ),
        backgroundCardCount: min(2, _scenarios.length - 1),
        backgroundCardOffset: const Offset(0, -30),
        backgroundCardScale: 0.9,
      ),
    );
  }

  Widget _buildScenarioCard(ScamScenario scenario, int index) {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(24),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [scenario.cardGradientStart, scenario.cardGradientEnd],
        ),
        border:
            Border.all(color: Colors.white.withOpacity(0.12), width: 1.5),
        boxShadow: [
          BoxShadow(
            color: scenario.iconColor.withOpacity(0.15),
            blurRadius: 30,
            offset: const Offset(0, 10),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Card number badge
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(12),
                color: Colors.white.withOpacity(0.08),
              ),
              child: Text(
                '${index + 1} / ${_scenarios.length}',
                style: TextStyle(
                  color: Colors.white.withOpacity(0.4),
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1,
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Large scenario icon
            Container(
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: scenario.iconColor.withOpacity(0.15),
                border: Border.all(
                  color: scenario.iconColor.withOpacity(0.3),
                  width: 2,
                ),
                boxShadow: [
                  BoxShadow(
                    color: scenario.iconColor.withOpacity(0.2),
                    blurRadius: 24,
                    spreadRadius: 4,
                  ),
                ],
              ),
              child:
                  Icon(scenario.icon, color: scenario.iconColor, size: 50),
            ),
            const SizedBox(height: 8),

            // Secondary visual cue (e.g., "FAKE LINK", "PLAY STORE")
            if (scenario.secondaryIcon != null)
              Padding(
                padding: const EdgeInsets.only(top: 4, bottom: 8),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      scenario.secondaryIcon,
                      color: scenario.iconColor.withOpacity(0.6),
                      size: 16,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      scenario.secondaryLabel ?? '',
                      style: TextStyle(
                        color: scenario.iconColor.withOpacity(0.6),
                        fontSize: 9,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.5,
                      ),
                    ),
                  ],
                ),
              ),

            const SizedBox(height: 8),

            // Title
            Text(
              scenario.title,
              textAlign: TextAlign.center,
              style: GoogleFonts.orbitron(
                color: Colors.white,
                fontSize: 15,
                fontWeight: FontWeight.w800,
                letterSpacing: 1.5,
              ),
            ),
            const SizedBox(height: 14),

            // Description — The scenario text
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(16),
                color: Colors.black.withOpacity(0.35),
                border:
                    Border.all(color: Colors.white.withOpacity(0.08)),
              ),
              child: Text(
                scenario.description,
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white.withOpacity(0.85),
                  fontSize: 15,
                  height: 1.6,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Question prompt
            Container(
              padding: const EdgeInsets.symmetric(
                horizontal: 16,
                vertical: 8,
              ),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(20),
                color: Colors.white.withOpacity(0.08),
              ),
              child: Text(
                'Is this SAFE or a SCAM?',
                style: GoogleFonts.orbitron(
                  color: Colors.white.withOpacity(0.6),
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 2,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── ACTION BUTTONS (Massive Red X / Green Check) ──────────────────────────
  Widget _buildActionButtons() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 8),
      child: AnimatedBuilder(
        animation: _buttonScale,
        builder: (_, __) => Row(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: [
            // SCAM (left swipe) — Massive Red X
            _actionButton(
              icon: Icons.close_rounded,
              label: 'SCAM',
              color: const Color(0xFFFF4D4D),
              onTap: () => _swiperCtrl.swipeLeft(),
              scale: _buttonScale.value,
            ),
            // SAFE (right swipe) — Massive Green Check
            _actionButton(
              icon: Icons.check_rounded,
              label: 'SAFE',
              color: const Color(0xFF00FFA3),
              onTap: () => _swiperCtrl.swipeRight(),
              scale: _buttonScale.value,
            ),
          ],
        ),
      ),
    );
  }

  Widget _actionButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
    double scale = 1.0,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Transform.scale(
        scale: scale,
        child: Column(
          children: [
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: color.withOpacity(0.15),
                border:
                    Border.all(color: color.withOpacity(0.5), width: 3),
                boxShadow: [
                  BoxShadow(
                    color: color.withOpacity(0.25),
                    blurRadius: 20,
                    spreadRadius: 3,
                  ),
                ],
              ),
              child: Icon(icon, color: color, size: 46),
            ),
            const SizedBox(height: 6),
            Text(
              label,
              style: TextStyle(
                color: color,
                fontSize: 12,
                fontWeight: FontWeight.w800,
                letterSpacing: 1.5,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── FEEDBACK OVERLAY ───────────────────────────────────────────────────────
  Widget _buildFeedbackOverlay() {
    final color = _feedbackCorrect
        ? const Color(0xFF00FFA3)
        : const Color(0xFFFF4D4D);
    final icon =
        _feedbackCorrect ? Icons.check_circle_rounded : Icons.cancel_rounded;
    final label = _feedbackCorrect ? 'CORRECT!' : 'WRONG!';

    return Positioned.fill(
      child: GestureDetector(
        onTap: () {
          _feedbackDismissTimer?.cancel();
          setState(() => _showFeedback = false);
          if (_totalAnswered >= _scenarios.length) {
            setState(() => _gameComplete = true);
            _speakScore();
          }
        },
        child: Container(
          color: Colors.black.withOpacity(0.85),
          child: ScaleTransition(
            scale: _feedbackScale,
            child: Center(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 28),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Massive result icon
                    Container(
                      width: 120,
                      height: 120,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: color.withOpacity(0.2),
                        boxShadow: [
                          BoxShadow(
                            color: color.withOpacity(0.4),
                            blurRadius: 50,
                            spreadRadius: 15,
                          ),
                        ],
                      ),
                      child: Icon(icon, color: color, size: 80),
                    ),
                    const SizedBox(height: 20),

                    // Label
                    Text(
                      label,
                      style: GoogleFonts.orbitron(
                        color: color,
                        fontSize: 30,
                        fontWeight: FontWeight.w900,
                        letterSpacing: 4,
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Explanation card with speaker indicator
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(16),
                        color: color.withOpacity(0.1),
                        border: Border.all(color: color.withOpacity(0.3)),
                      ),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Icon(
                            _isSpeaking
                                ? Icons.volume_up_rounded
                                : Icons.info_outline_rounded,
                            color: color.withOpacity(0.7),
                            size: 24,
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              _feedbackText,
                              style: TextStyle(
                                color: Colors.white.withOpacity(0.85),
                                fontSize: 14,
                                height: 1.5,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 14),

                    // Speaking indicator
                    if (_isSpeaking)
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            Icons.volume_up_rounded,
                            color: Colors.white.withOpacity(0.4),
                            size: 16,
                          ),
                          const SizedBox(width: 6),
                          Text(
                            'Speaking…',
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.4),
                              fontSize: 11,
                              fontStyle: FontStyle.italic,
                            ),
                          ),
                        ],
                      ),
                    const SizedBox(height: 8),

                    Text(
                      'Tap anywhere to continue',
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.3),
                        fontSize: 11,
                        letterSpacing: 0.5,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  // ── GAME COMPLETE ──────────────────────────────────────────────────────────
  Widget _buildGameComplete() {
    final perfect = _score == _scenarios.length;
    final color = perfect ? const Color(0xFF00FFA3) : const Color(0xFF00D4FF);

    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 28),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Trophy / Shield icon
            AnimatedBuilder(
              animation: _pulse,
              builder: (_, __) => Container(
                width: 120,
                height: 120,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: color.withOpacity(0.15),
                  boxShadow: [
                    BoxShadow(
                      color: color.withOpacity(0.3 * _pulse.value),
                      blurRadius: 40,
                      spreadRadius: 10,
                    ),
                  ],
                ),
                child: Icon(
                  perfect
                      ? Icons.emoji_events_rounded
                      : Icons.shield_rounded,
                  color: color,
                  size: 64,
                ),
              ),
            ),
            const SizedBox(height: 24),

            Text(
              perfect ? 'PERFECT SCORE!' : 'TRAINING COMPLETE',
              style: GoogleFonts.orbitron(
                color: color,
                fontSize: 20,
                fontWeight: FontWeight.w900,
                letterSpacing: 3,
              ),
            ),
            const SizedBox(height: 12),

            Text(
              'You scored $_score out of ${_scenarios.length}',
              style: TextStyle(
                color: Colors.white.withOpacity(0.7),
                fontSize: 16,
                fontWeight: FontWeight.w500,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              perfect
                  ? 'You are a scam detection expert!'
                  : 'Practice more to protect your money.',
              style: TextStyle(
                color: Colors.white.withOpacity(0.4),
                fontSize: 13,
              ),
            ),
            const SizedBox(height: 32),

            // Play Again button
            GestureDetector(
              onTap: _resetGame,
              child: Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 32,
                  vertical: 16,
                ),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(16),
                  gradient: LinearGradient(
                    colors: [color, color.withOpacity(0.7)],
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: color.withOpacity(0.3),
                      blurRadius: 16,
                      offset: const Offset(0, 4),
                    ),
                  ],
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.replay_rounded,
                        color: Color(0xFF0B101E), size: 22),
                    const SizedBox(width: 10),
                    Text(
                      'PLAY AGAIN',
                      style: GoogleFonts.orbitron(
                        color: const Color(0xFF0B101E),
                        fontSize: 13,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 2,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
