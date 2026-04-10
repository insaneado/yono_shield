// ============================================================================
// YONO SHIELD — ThreatCard Widget
// ============================================================================
// A glassmorphism-styled card for displaying scanned app results with
// risk-level color coding. Used in the Clone Radar tab.
// ============================================================================

import 'dart:ui';
import 'package:flutter/material.dart';
import '../models/app_scan_result.dart';

class ThreatCard extends StatelessWidget {
  final AppScanResult app;

  const ThreatCard({super.key, required this.app});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(16),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: _riskBorderColor.withOpacity(0.4),
                width: 1.5,
              ),
              gradient: LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  _riskBgColor.withOpacity(0.15),
                  _riskBgColor.withOpacity(0.05),
                ],
              ),
            ),
            child: Row(
              children: [
                // Risk level icon
                _buildRiskIcon(),
                const SizedBox(width: 14),

                // App info
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // App name
                      Text(
                        app.appName,
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                          letterSpacing: 0.3,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),

                      // Package name
                      Text(
                        app.packageName,
                        style: TextStyle(
                          color: Colors.white.withOpacity(0.5),
                          fontSize: 11,
                          fontFamily: 'monospace',
                          letterSpacing: 0.5,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 6),

                      // Risk reason
                      Text(
                        app.riskReason,
                        style: TextStyle(
                          color: _riskTextColor.withOpacity(0.9),
                          fontSize: 12,
                          fontWeight: FontWeight.w500,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),

                const SizedBox(width: 12),

                // Risk badge
                _buildRiskBadge(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// Build the risk level icon on the left side of the card.
  Widget _buildRiskIcon() {
    final IconData icon;
    switch (app.riskLevel) {
      case RiskLevel.dangerous:
        icon = Icons.dangerous_rounded;
        break;
      case RiskLevel.suspicious:
        icon = Icons.warning_amber_rounded;
        break;
      case RiskLevel.safe:
        icon = Icons.verified_user_rounded;
        break;
    }

    return Container(
      width: 44,
      height: 44,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: _riskBgColor.withOpacity(0.2),
        border: Border.all(color: _riskBorderColor.withOpacity(0.3)),
      ),
      child: Icon(icon, color: _riskBorderColor, size: 22),
    );
  }

  /// Build the risk level badge on the right side of the card.
  Widget _buildRiskBadge() {
    final String label;
    switch (app.riskLevel) {
      case RiskLevel.dangerous:
        label = 'DANGER';
        break;
      case RiskLevel.suspicious:
        label = 'SUSPECT';
        break;
      case RiskLevel.safe:
        label = 'SAFE';
        break;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(20),
        color: _riskBgColor.withOpacity(0.25),
        border: Border.all(color: _riskBorderColor.withOpacity(0.5)),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: _riskBorderColor,
          fontSize: 10,
          fontWeight: FontWeight.w800,
          letterSpacing: 1.2,
        ),
      ),
    );
  }

  // Color helpers based on risk level
  Color get _riskBorderColor {
    switch (app.riskLevel) {
      case RiskLevel.dangerous:
        return const Color(0xFFFF3B3B);
      case RiskLevel.suspicious:
        return const Color(0xFFFF9F1C);
      case RiskLevel.safe:
        return const Color(0xFF00FF88);
    }
  }

  Color get _riskBgColor {
    switch (app.riskLevel) {
      case RiskLevel.dangerous:
        return const Color(0xFFFF3B3B);
      case RiskLevel.suspicious:
        return const Color(0xFFFF9F1C);
      case RiskLevel.safe:
        return const Color(0xFF00FF88);
    }
  }

  Color get _riskTextColor {
    switch (app.riskLevel) {
      case RiskLevel.dangerous:
        return const Color(0xFFFF6B6B);
      case RiskLevel.suspicious:
        return const Color(0xFFFFBF69);
      case RiskLevel.safe:
        return const Color(0xFF88FFBB);
    }
  }
}
