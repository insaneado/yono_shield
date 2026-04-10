// ============================================================================
// YONO SHIELD — PhishingAlert Widget
// ============================================================================
// A massive, animated red warning card that appears when phishing content
// is detected in an intercepted SMS. Features a pulsing animation and
// displays the detected indicators.
// ============================================================================

import 'package:flutter/material.dart';
import '../models/sms_alert.dart';

class PhishingAlert extends StatefulWidget {
  final SmsAlert alert;
  final VoidCallback? onDismiss;

  const PhishingAlert({
    super.key,
    required this.alert,
    this.onDismiss,
  });

  @override
  State<PhishingAlert> createState() => _PhishingAlertState();
}

class _PhishingAlertState extends State<PhishingAlert>
    with SingleTickerProviderStateMixin {
  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;
  late Animation<double> _glowAnimation;

  @override
  void initState() {
    super.initState();

    // Pulsing animation — creates the urgent feeling
    _pulseController = AnimationController(
      duration: const Duration(milliseconds: 1200),
      vsync: this,
    )..repeat(reverse: true);

    _pulseAnimation = Tween<double>(begin: 1.0, end: 1.03).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );

    _glowAnimation = Tween<double>(begin: 0.3, end: 0.8).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isPhishing = widget.alert.threatLevel == SmsThreatLevel.phishing;
    final isWarning = widget.alert.threatLevel == SmsThreatLevel.warning;

    final Color primaryColor =
        isPhishing ? const Color(0xFFFF1744) : const Color(0xFFFF9100);
    final Color bgColor =
        isPhishing ? const Color(0xFF2D0000) : const Color(0xFF2D1800);

    return AnimatedBuilder(
      animation: _pulseController,
      builder: (context, child) {
        return Transform.scale(
          scale: (isPhishing || isWarning) ? _pulseAnimation.value : 1.0,
          child: Container(
            margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(20),
              color: bgColor,
              border: Border.all(
                color: primaryColor.withOpacity(_glowAnimation.value),
                width: 2,
              ),
              boxShadow: [
                BoxShadow(
                  color: primaryColor.withOpacity(_glowAnimation.value * 0.4),
                  blurRadius: 20,
                  spreadRadius: 2,
                ),
              ],
            ),
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // ============================================================
                  // HEADER — Alert icon + title
                  // ============================================================
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: primaryColor.withOpacity(0.2),
                        ),
                        child: Icon(
                          isPhishing
                              ? Icons.gpp_bad_rounded
                              : Icons.warning_amber_rounded,
                          color: primaryColor,
                          size: 28,
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              isPhishing
                                  ? '🚨 PHISHING ALERT'
                                  : '⚠️ SUSPICIOUS MESSAGE',
                              style: TextStyle(
                                color: primaryColor,
                                fontSize: isPhishing ? 20 : 18,
                                fontWeight: FontWeight.w900,
                                letterSpacing: 1.5,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              'Confidence: ${(widget.alert.confidenceScore * 100).toStringAsFixed(0)}%',
                              style: TextStyle(
                                color: primaryColor.withOpacity(0.7),
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ],
                        ),
                      ),
                      if (widget.onDismiss != null)
                        IconButton(
                          onPressed: widget.onDismiss,
                          icon: Icon(Icons.close,
                              color: Colors.white.withOpacity(0.5), size: 20),
                        ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // ============================================================
                  // SENDER
                  // ============================================================
                  Row(
                    children: [
                      Icon(Icons.person_outline,
                          color: Colors.white.withOpacity(0.5), size: 16),
                      const SizedBox(width: 6),
                      Text(
                        'From: ${widget.alert.sender}',
                        style: TextStyle(
                          color: Colors.white.withOpacity(0.7),
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),

                  // ============================================================
                  // MESSAGE BODY — Displayed in a dark box
                  // ============================================================
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(12),
                      color: Colors.black.withOpacity(0.4),
                      border: Border.all(
                          color: Colors.white.withOpacity(0.1)),
                    ),
                    child: Text(
                      widget.alert.messageBody,
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.85),
                        fontSize: 13,
                        height: 1.5,
                      ),
                      maxLines: 5,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  const SizedBox(height: 14),

                  // ============================================================
                  // DETECTED INDICATORS — Chip list
                  // ============================================================
                  if (widget.alert.detectedIndicators.isNotEmpty) ...[
                    Text(
                      'DETECTED INDICATORS:',
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.5),
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.5,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: widget.alert.detectedIndicators
                          .map((indicator) => Container(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 10, vertical: 5),
                                decoration: BoxDecoration(
                                  borderRadius: BorderRadius.circular(20),
                                  color: primaryColor.withOpacity(0.15),
                                  border: Border.all(
                                      color: primaryColor.withOpacity(0.3)),
                                ),
                                child: Text(
                                  indicator,
                                  style: TextStyle(
                                    color: primaryColor.withOpacity(0.9),
                                    fontSize: 11,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ))
                          .toList(),
                    ),
                  ],

                  const SizedBox(height: 12),

                  // ============================================================
                  // TIMESTAMP
                  // ============================================================
                  Text(
                    'Intercepted: ${_formatTime(widget.alert.timestamp)}',
                    style: TextStyle(
                      color: Colors.white.withOpacity(0.3),
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  String _formatTime(DateTime dt) {
    final h = dt.hour.toString().padLeft(2, '0');
    final m = dt.minute.toString().padLeft(2, '0');
    final s = dt.second.toString().padLeft(2, '0');
    return '$h:$m:$s';
  }
}
