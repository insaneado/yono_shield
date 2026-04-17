// ============================================================================
// YONO SHIELD — Scam Simulator Page (Wrapper)
// ============================================================================
//
// Thin page wrapper that embeds the standalone ScamGame widget.
// This file exists so the SecurityDashboard's PageView can import it as a
// page alongside RadarPage, SmsPage, and OverlayPage.
//
// The actual game logic and UI live in:
//   lib/widgets/scam_game.dart → ScamGame
// ============================================================================

import 'package:flutter/material.dart';
import '../widgets/scam_game.dart';

class ScamGamePage extends StatelessWidget {
  const ScamGamePage({super.key});

  @override
  Widget build(BuildContext context) {
    return const ScamGame();
  }
}
