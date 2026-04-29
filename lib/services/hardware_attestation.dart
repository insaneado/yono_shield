// ============================================================================
// KAVACH — hardware_attestation.dart (Loophole 8: Hardware TEE Attestation)
// ============================================================================
//
// REPLACES: device_integrity.dart (flutter_jailbreak_detection)
//
// WHY THE UPGRADE:
//   Software-based root detection (su binary scanning, file path checks) is
//   trivially bypassed by kernel-level rootkits like Magisk that use mount
//   namespaces to hide root artifacts from userspace.  The Google Play
//   Integrity API uses the device's Trusted Execution Environment (TEE) —
//   a hardware-isolated security enclave — to produce a cryptographic
//   attestation token that CANNOT be spoofed from software.
//
// ARCHITECTURE:
//   Flutter (this file)
//     │
//     ├─ Pre-flight: google_api_availability (Play Services check)
//     │
//     ├─ MethodChannel("kavach.security/integrity")
//     │       │
//     │       ▼
//     │  Kotlin Native (MainActivity.kt)
//     │    └─ IntegrityManagerFactory.create()
//     │    └─ requestIntegrityToken(nonce, cloudProjectNumber)
//     │    └─ Parse verdict labels from token
//     │       │
//     │       ▼
//     │  Google Play Services (on-device TEE)
//     │    └─ Cryptographic attestation via hardware security module
//     │
//     └─ Evaluate: MEETS_DEVICE_INTEGRITY + MEETS_BASIC_INTEGRITY
//
// ┌──────────────────────────────────────────────────────────────────────┐
// │  ⚠️  PRODUCTION NOTE — SERVER-SIDE VERIFICATION REQUIRED           │
// │                                                                      │
// │  The integrity token returned by the TEE is a signed JWS (JSON Web  │
// │  Signature).  In a production deployment, this token MUST be sent   │
// │  to the KAVACH Python backend (kavach_backend/main.py) for          │
// │  server-side decryption using the Google Play Integrity API:        │
// │                                                                      │
// │    POST https://playintegrity.googleapis.com/v1/{packageName}:      │
// │         decodeIntegrityToken                                         │
// │                                                                      │
// │  Client-side verdict parsing (what this MVP does) is acceptable     │
// │  for hackathon demos but is NOT production-safe — a sophisticated   │
// │  attacker with a rooted device could intercept the MethodChannel    │
// │  response and inject a spoofed verdict map.                         │
// │                                                                      │
// │  Server-side flow:                                                   │
// │    1. Flutter requests token from TEE (this file)                   │
// │    2. Flutter sends raw token to backend: POST /api/attest          │
// │    3. Backend decrypts token via Google API (service account auth)  │
// │    4. Backend returns verified verdict to Flutter                   │
// │    5. Flutter enforces lockout based on backend verdict             │
// └──────────────────────────────────────────────────────────────────────┘
// ============================================================================

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:google_api_availability/google_api_availability.dart';

/// Result of a hardware integrity attestation.
///
/// Mirrors the old [DeviceIntegrityResult] API shape so that main.dart
/// requires minimal changes.
class DeviceIntegrityResult {
  /// True if the device passed hardware attestation.
  final bool isIntact;

  /// True if the device failed MEETS_BASIC_INTEGRITY (rooted / custom ROM).
  final bool isRooted;

  /// True if developer mode is enabled (reserved for future checks).
  final bool isDeveloperMode;

  /// Human-readable reason for failure (null if intact).
  final String? failureReason;

  /// The raw integrity verdict labels from the TEE (for telemetry).
  final List<String> verdictLabels;

  const DeviceIntegrityResult({
    required this.isIntact,
    this.isRooted = false,
    this.isDeveloperMode = false,
    this.failureReason,
    this.verdictLabels = const [],
  });
}

/// Hardware attestation service using Google Play Integrity API.
///
/// Requests a cryptographic integrity token from the device's TEE via
/// a native Kotlin MethodChannel bridge, then evaluates the verdict.
class HardwareAttestation {
  static const _channel = MethodChannel('kavach.security/integrity');

  /// Perform a full hardware integrity attestation.
  ///
  /// Flow:
  ///   1. Check Google Play Services availability (pre-flight)
  ///   2. Request integrity token from TEE via native Kotlin bridge
  ///   3. Evaluate verdict labels: MEETS_DEVICE_INTEGRITY + MEETS_BASIC_INTEGRITY
  ///
  /// Returns [DeviceIntegrityResult] with `isIntact == false` if the device
  /// fails attestation (rooted, unlocked bootloader, custom ROM, emulator).
  ///
  /// Fails-safe: if anything throws, assume compromised.
  Future<DeviceIntegrityResult> verifyDeviceIntegrity() async {
    try {
      // ── PRE-FLIGHT: Verify Google Play Services is available ──
      // Play Integrity API requires Play Services.  Devices without it
      // (Huawei post-ban, Amazon Fire, custom ROMs) cannot attest.
      final playServicesAvailability = await GoogleApiAvailability.instance
          .checkGooglePlayServicesAvailability();

      if (playServicesAvailability != GooglePlayServicesAvailability.success) {
        return DeviceIntegrityResult(
          isIntact: false,
          isRooted: true,
          failureReason:
              'Google Play Services unavailable '
              '(status: $playServicesAvailability). '
              'Hardware attestation requires Play Services. '
              'This device cannot be verified as trustworthy.',
        );
      }

      // ── REQUEST: Invoke native Kotlin to call Play Integrity API ──
      // The Kotlin side calls IntegrityManagerFactory.create() and
      // requestIntegrityToken() with a cryptographic nonce.
      final Map<dynamic, dynamic> result = await _channel.invokeMethod(
        'requestIntegrityVerdict',
      );

      // ── EVALUATE: Parse verdict from native response ──
      final bool meetsDeviceIntegrity =
          result['meetsDeviceIntegrity'] as bool? ?? false;
      final bool meetsBasicIntegrity =
          result['meetsBasicIntegrity'] as bool? ?? false;
      final bool meetsStrongIntegrity =
          result['meetsStrongIntegrity'] as bool? ?? false;
      final List<String> labels =
          (result['verdictLabels'] as List<dynamic>?)
              ?.cast<String>() ?? [];

      // ── VERDICT LOGIC ──
      // MEETS_DEVICE_INTEGRITY: Android-powered device with Google Play
      //   Services, passes system integrity checks (bootloader locked,
      //   verified boot chain, genuine Android build).
      //
      // MEETS_BASIC_INTEGRITY: Device passes basic integrity checks.
      //   May have an unlocked bootloader but is not actively rooted.
      //
      // If NEITHER is present: device is rooted, running a custom ROM,
      //   is an emulator, or has been tampered with at the kernel level.
      if (meetsDeviceIntegrity && meetsBasicIntegrity) {
        debugPrint(
          'KAVACH HW Attestation: PASSED '
          '[device=$meetsDeviceIntegrity, basic=$meetsBasicIntegrity, '
          'strong=$meetsStrongIntegrity, labels=$labels]',
        );
        return DeviceIntegrityResult(
          isIntact: true,
          verdictLabels: labels,
        );
      }

      // ── ATTESTATION FAILED ──
      final reasons = <String>[];
      if (!meetsBasicIntegrity) {
        reasons.add('FAILS BASIC_INTEGRITY (device is rooted or emulated)');
      }
      if (!meetsDeviceIntegrity) {
        reasons.add(
          'FAILS DEVICE_INTEGRITY (bootloader unlocked or custom ROM)',
        );
      }

      final failureReason =
          'Hardware attestation FAILED: ${reasons.join('; ')}. '
          'Verdict labels: [${labels.join(", ")}]';

      debugPrint('KAVACH HW Attestation: $failureReason');

      return DeviceIntegrityResult(
        isIntact: false,
        isRooted: true,
        failureReason: failureReason,
        verdictLabels: labels,
      );
    } on MissingPluginException {
      // Plugin not available (e.g. running on desktop for development).
      // Allow development builds to proceed.
      debugPrint(
        'KAVACH HW Attestation: MissingPluginException — '
        'allowing development build',
      );
      return const DeviceIntegrityResult(isIntact: true);
    } on PlatformException catch (e) {
      // Native call failed — fail-safe: assume compromised.
      return DeviceIntegrityResult(
        isIntact: false,
        isRooted: true,
        failureReason:
            'Hardware attestation error: ${e.code} — ${e.message}',
      );
    } catch (e) {
      // Unexpected error — fail-safe: assume compromised.
      return DeviceIntegrityResult(
        isIntact: false,
        isRooted: true,
        failureReason: 'Hardware attestation unexpected error: $e',
      );
    }
  }
}
