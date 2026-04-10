// ============================================================================
// YONO SHIELD — Overlay Control Page (Placeholder)
// ============================================================================
import 'package:flutter/material.dart';

class OverlayPage extends StatelessWidget {
  const OverlayPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    const Color(0xFFFF4D4D).withOpacity(0.2),
                    const Color(0xFFFF9F1C).withOpacity(0.1),
                  ],
                ),
                border: Border.all(
                    color: const Color(0xFFFF4D4D).withOpacity(0.3), width: 2),
              ),
              child: const Icon(Icons.layers_rounded,
                  color: Color(0xFFFF4D4D), size: 44),
            ),
            const SizedBox(height: 24),
            Text(
              'THREAT SHIELD',
              style: TextStyle(
                color: const Color(0xFF00FFA3).withOpacity(0.9),
                fontSize: 18,
                fontWeight: FontWeight.w800,
                letterSpacing: 3,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'Draws a full-screen blocking overlay\nover malicious apps using\nSYSTEM_ALERT_WINDOW.',
              style: TextStyle(
                  color: Colors.white.withOpacity(0.5),
                  fontSize: 13,
                  height: 1.6),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 32),
            // Permission card
            Container(
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
                          color: Colors.red.withOpacity(0.15),
                        ),
                        child: const Icon(Icons.lock_rounded,
                            color: Colors.red, size: 22),
                      ),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text('SYSTEM_ALERT_WINDOW',
                                style: TextStyle(
                                    color: Colors.white,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w700)),
                            const SizedBox(height: 3),
                            Text('Required to display blocking overlay',
                                style: TextStyle(
                                    color: Colors.white.withOpacity(0.5),
                                    fontSize: 12)),
                          ],
                        ),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 10, vertical: 5),
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(20),
                          color: Colors.red.withOpacity(0.15),
                        ),
                        child: const Text('OFF',
                            style: TextStyle(
                                color: Colors.red,
                                fontSize: 11,
                                fontWeight: FontWeight.w800)),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(12),
                      gradient: const LinearGradient(
                          colors: [Color(0xFFFF9F1C), Color(0xFFFF6B35)]),
                    ),
                    child: const Center(
                      child: Text('GRANT PERMISSION',
                          style: TextStyle(
                              color: Colors.white,
                              fontSize: 13,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 1.5)),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),
            // How it works
            Container(
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
                        color: const Color(0xFF00D4FF).withOpacity(0.7),
                        size: 18),
                    const SizedBox(width: 8),
                    Text('HOW IT WORKS',
                        style: TextStyle(
                            color: const Color(0xFF00D4FF).withOpacity(0.9),
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 1.5)),
                  ]),
                  const SizedBox(height: 14),
                  _step('1',
                      'When a tampered app is detected, the overlay activates.'),
                  _step('2',
                      'A full-screen red warning blocks access to the threat.'),
                  _step('3',
                      'User must dismiss to return — preventing data entry.'),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

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
                        fontWeight: FontWeight.w700))),
          ),
          const SizedBox(width: 10),
          Expanded(
              child: Text(t,
                  style: TextStyle(
                      color: Colors.white.withOpacity(0.5),
                      fontSize: 12,
                      height: 1.5))),
        ]),
      );
}
