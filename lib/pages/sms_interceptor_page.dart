// ============================================================================
// YONO SHIELD — SMS Interceptor Page (Placeholder)
// ============================================================================
import 'package:flutter/material.dart';

class SmsPage extends StatelessWidget {
  const SmsPage({super.key});

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
                color: const Color(0xFF00FFA3).withOpacity(0.1),
                border: Border.all(
                    color: const Color(0xFF00FFA3).withOpacity(0.3), width: 2),
              ),
              child: const Icon(Icons.sms_rounded,
                  color: Color(0xFF00FFA3), size: 44),
            ),
            const SizedBox(height: 24),
            Text(
              'SMS INTERCEPTOR',
              style: TextStyle(
                color: const Color(0xFF00FFA3).withOpacity(0.9),
                fontSize: 18,
                fontWeight: FontWeight.w800,
                letterSpacing: 3,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'Monitors incoming SMS for phishing links\ncontaining KYC scams, fake OTP requests,\nand suspicious shortened URLs.',
              style: TextStyle(
                  color: Colors.white.withOpacity(0.5),
                  fontSize: 13,
                  height: 1.6),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 32),
            // Toggle placeholder
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(16),
                color: Colors.white.withOpacity(0.05),
                border: Border.all(color: Colors.white.withOpacity(0.1)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.lock_open_rounded,
                      color: const Color(0xFFFF9F1C).withOpacity(0.8),
                      size: 20),
                  const SizedBox(width: 12),
                  Text(
                    'GRANT SMS PERMISSION',
                    style: TextStyle(
                      color: const Color(0xFFFF9F1C).withOpacity(0.9),
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(12),
                color: const Color(0xFF00FFA3).withOpacity(0.08),
              ),
              child: const Text(
                'STATUS: STANDBY',
                style: TextStyle(
                  color: Color(0xFF00FFA3),
                  fontSize: 11,
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
}
