// ============================================================================
// YONO SHIELD — ScanAnimation Widget
// ============================================================================
// An animated radar/scanning visual used in the Clone Radar tab while
// a scan is in progress. Features a rotating sweep line and concentric
// rings for a cybersecurity aesthetic.
// ============================================================================

import 'dart:math';
import 'package:flutter/material.dart';

class ScanAnimation extends StatefulWidget {
  /// Whether the scan is currently active
  final bool isScanning;

  /// Size of the radar animation
  final double size;

  const ScanAnimation({
    super.key,
    required this.isScanning,
    this.size = 180,
  });

  @override
  State<ScanAnimation> createState() => _ScanAnimationState();
}

class _ScanAnimationState extends State<ScanAnimation>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    );

    if (widget.isScanning) {
      _controller.repeat();
    }
  }

  @override
  void didUpdateWidget(ScanAnimation oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.isScanning && !oldWidget.isScanning) {
      _controller.repeat();
    } else if (!widget.isScanning && oldWidget.isScanning) {
      _controller.stop();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: widget.size,
      height: widget.size,
      child: AnimatedBuilder(
        animation: _controller,
        builder: (context, child) {
          return CustomPaint(
            painter: _RadarPainter(
              sweepAngle: _controller.value * 2 * pi,
              isActive: widget.isScanning,
            ),
            size: Size(widget.size, widget.size),
          );
        },
      ),
    );
  }
}

/// Custom painter for the radar sweep animation.
class _RadarPainter extends CustomPainter {
  final double sweepAngle;
  final bool isActive;

  _RadarPainter({required this.sweepAngle, required this.isActive});

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final maxRadius = size.width / 2;

    // ======================================================================
    // CONCENTRIC RINGS — Radar grid
    // ======================================================================
    final ringPaint = Paint()
      ..color = const Color(0xFF00FF88).withOpacity(isActive ? 0.2 : 0.1)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;

    for (int i = 1; i <= 4; i++) {
      canvas.drawCircle(center, maxRadius * (i / 4), ringPaint);
    }

    // ======================================================================
    // CROSS HAIRS — Horizontal and vertical lines
    // ======================================================================
    final crossPaint = Paint()
      ..color = const Color(0xFF00FF88).withOpacity(0.1)
      ..strokeWidth = 0.5;

    canvas.drawLine(
        Offset(0, center.dy), Offset(size.width, center.dy), crossPaint);
    canvas.drawLine(
        Offset(center.dx, 0), Offset(center.dx, size.height), crossPaint);

    if (!isActive) {
      // Draw a static shield icon in the center when not scanning
      final shieldPaint = Paint()
        ..color = const Color(0xFF00FF88).withOpacity(0.3)
        ..style = PaintingStyle.fill;
      canvas.drawCircle(center, 8, shieldPaint);
      return;
    }

    // ======================================================================
    // SWEEP LINE — Rotating radar beam
    // ======================================================================
    final sweepEndX = center.dx + maxRadius * cos(sweepAngle - pi / 2);
    final sweepEndY = center.dy + maxRadius * sin(sweepAngle - pi / 2);

    final sweepPaint = Paint()
      ..color = const Color(0xFF00FF88)
      ..strokeWidth = 2
      ..style = PaintingStyle.stroke;

    canvas.drawLine(center, Offset(sweepEndX, sweepEndY), sweepPaint);

    // ======================================================================
    // SWEEP GRADIENT — Trailing glow behind the sweep line
    // ======================================================================
    final sweepGradient = SweepGradient(
      center: Alignment.center,
      startAngle: sweepAngle - pi / 3,
      endAngle: sweepAngle,
      colors: [
        const Color(0xFF00FF88).withOpacity(0.0),
        const Color(0xFF00FF88).withOpacity(0.15),
      ],
      transform: const GradientRotation(-pi / 2),
    );

    final gradientPaint = Paint()
      ..shader = sweepGradient
          .createShader(Rect.fromCircle(center: center, radius: maxRadius))
      ..style = PaintingStyle.fill;

    canvas.drawCircle(center, maxRadius, gradientPaint);

    // ======================================================================
    // CENTER DOT — Pulsing center point
    // ======================================================================
    final dotPaint = Paint()
      ..color = const Color(0xFF00FF88)
      ..style = PaintingStyle.fill;

    canvas.drawCircle(center, 4, dotPaint);

    // Outer glow
    final glowPaint = Paint()
      ..color = const Color(0xFF00FF88).withOpacity(0.3)
      ..style = PaintingStyle.fill;

    canvas.drawCircle(center, 8, glowPaint);
  }

  @override
  bool shouldRepaint(covariant _RadarPainter oldDelegate) {
    return oldDelegate.sweepAngle != sweepAngle ||
        oldDelegate.isActive != isActive;
  }
}
