// ============================================================================
// KAVACH — device_integrity.dart (Loophole 8: Root/Jailbreak Detection)
// ============================================================================
//
// Verifies the physical integrity of the device OS before allowing banking
// operations.  A rooted or jailbroken device grants malicious actors
// kernel-level access to bypass sandboxing, intercept IPC, and steal
// credentials directly from memory.
//
// Uses flutter_jailbreak_detection which checks for:
//   - su binary presence (Magisk, SuperSU, KingRoot, etc.)
//   - RW-mounted /system partition
//   - Known root management apps (Magisk Manager, etc.)
//   - Test-keys build signatures (custom ROMs)
//   - Developer mode / USB debugging status
// ============================================================================

import 'package:flutter/services.dart';
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

/// Result of a device integrity check.
class DeviceIntegrityResult {
  /// True if the device passed all integrity checks.
  final bool isIntact;

  /// True if root / jailbreak was detected.
  final bool isRooted;

  /// True if developer mode is enabled.
  final bool isDeveloperMode;

  /// Human-readable reason for failure (null if intact).
  final String? failureReason;

  const DeviceIntegrityResult({
    required this.isIntact,
    this.isRooted = false,
    this.isDeveloperMode = false,
    this.failureReason,
  });
}

/// Stateless service that checks device OS integrity.
class DeviceIntegrity {
  /// Perform a full device integrity check.
  ///
  /// Returns [DeviceIntegrityResult] with `isIntact == false` if the device
  /// is rooted/jailbroken or developer mode is enabled.
  ///
  /// Fails-safe: if the native plugin throws, assume compromised.
  Future<DeviceIntegrityResult> verifyDeviceIntegrity() async {
    try {
      final bool isJailbroken = await FlutterJailbreakDetection.jailbroken;
      final bool isDeveloperMode = await FlutterJailbreakDetection.developerMode;

      if (isJailbroken) {
        return const DeviceIntegrityResult(
          isIntact: false,
          isRooted: true,
          failureReason:
              'Root/Jailbreak detected. Device OS has been modified, '
              'allowing malicious actors to bypass security sandboxing.',
        );
      }

      if (isDeveloperMode) {
        return const DeviceIntegrityResult(
          isIntact: false,
          isDeveloperMode: true,
          failureReason:
              'Developer mode is enabled. USB debugging allows external '
              'programs to control the device and intercept banking data.',
        );
      }

      return const DeviceIntegrityResult(isIntact: true);
    } on MissingPluginException {
      // Plugin not available on this platform (e.g. desktop) — treat as safe
      // for development builds.
      return const DeviceIntegrityResult(isIntact: true);
    } on PlatformException catch (e) {
      // Native check failed — fail-safe: assume compromised.
      return DeviceIntegrityResult(
        isIntact: false,
        isRooted: true,
        failureReason: 'Integrity check failed: ${e.message}',
      );
    } catch (e) {
      // Unexpected error — fail-safe.
      return DeviceIntegrityResult(
        isIntact: false,
        isRooted: true,
        failureReason: 'Integrity check error: $e',
      );
    }
  }
}
