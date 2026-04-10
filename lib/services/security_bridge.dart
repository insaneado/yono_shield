// ============================================================================
// YONO SHIELD — SecurityBridge (v3 — Cryptographic Gatekeeper Integration)
// ============================================================================
// Singleton service wrapping the MethodChannel to native Kotlin.
// All Flutter pages call this instead of invoking channels directly.
//
// LAYER 3 ADDITIONS:
//   - isDeviceRooted()       → boolean root detection
//   - verifyAppSecurity()    → master gatekeeper (root + signature check)
// ============================================================================

import 'package:flutter/services.dart';

class SecurityBridge {
  static final SecurityBridge _instance = SecurityBridge._internal();
  factory SecurityBridge() => _instance;
  SecurityBridge._internal();

  static const MethodChannel _channel =
      MethodChannel('com.yonoshield.security/bridge');

  // ==========================================================================
  // LAYER 3 — Cryptographic Gatekeeper
  // ==========================================================================

  /// Check if the device is rooted.
  /// Returns true if root indicators are detected (test-keys, su binaries,
  /// root management packages).
  Future<bool> isDeviceRooted() async {
    try {
      final result = await _channel.invokeMethod('isDeviceRooted');
      return result as bool? ?? false;
    } on MissingPluginException {
      return false; // Web/desktop fallback — assume not rooted
    } on PlatformException catch (e) {
      throw Exception('Root detection failed: ${e.message}');
    }
  }

  /// Master security verification — the Cryptographic Gatekeeper.
  ///
  /// Invokes the native `verifyAppSecurity` method which:
  ///   1. Checks if the device is rooted → returns "ROOTED_DEVICE"
  ///   2. Extracts SHA-256 signing cert hash of the target app
  ///   3. Compares against known-good official hash
  ///
  /// Returns a Map with keys:
  ///   - verdict:      "SAFE" | "ROOTED_DEVICE" | "INVALID_SIGNATURE" | "APP_NOT_FOUND"
  ///   - packageName:  the queried package
  ///   - isRooted:     boolean
  ///   - liveHash:     the extracted SHA-256 hash (nullable)
  ///   - expectedHash: the official reference hash
  ///   - message:      human-readable status message
  Future<Map<String, dynamic>> verifyAppSecurity(String packageName) async {
    try {
      final result = await _channel.invokeMethod(
        'verifyAppSecurity',
        {'packageName': packageName},
      );
      return Map<String, dynamic>.from(result as Map);
    } on MissingPluginException {
      // Web/desktop fallback — simulate a safe response
      return {
        'verdict': 'PLATFORM_UNSUPPORTED',
        'packageName': packageName,
        'isRooted': false,
        'liveHash': null,
        'expectedHash': 'UNAVAILABLE',
        'message': 'Native security bridge not available on this platform.',
      };
    } on PlatformException catch (e) {
      throw Exception('Security verification failed: ${e.message}');
    }
  }

  // ==========================================================================
  // EXISTING — Package Scanning & Legacy Signature Verification
  // ==========================================================================

  /// Get all user-installed (non-system) packages.
  /// Returns List<Map> with "packageName" and "appName" keys.
  Future<List<Map<String, dynamic>>> getInstalledPackages() async {
    try {
      final result = await _channel.invokeMethod('getInstalledPackages');
      if (result is List) {
        return result
            .map((e) => Map<String, dynamic>.from(e as Map))
            .toList();
      }
      return [];
    } on MissingPluginException {
      return []; // Web/desktop fallback
    } on PlatformException catch (e) {
      throw Exception('Scan failed: ${e.message}');
    }
  }

  /// Get the SHA-256 signing certificate hash of a specific app.
  /// Returns hex string like "AA:BB:CC:..." or null if not found.
  Future<String?> getAppSignatureHash(String packageName) async {
    try {
      final result = await _channel.invokeMethod(
        'getAppSignatureHash',
        {'packageName': packageName},
      );
      return result as String?;
    } on MissingPluginException {
      return null;
    } on PlatformException catch (e) {
      throw Exception('Hash extraction failed: ${e.message}');
    }
  }

  /// Legacy: Verify an app's signing certificate against known-good hashes.
  /// Returns a Map with: packageName, appName, isVerified, liveHash,
  /// expectedHash, verdict.
  Future<Map<String, dynamic>> verifyAppSignature(String packageName) async {
    try {
      final result = await _channel.invokeMethod(
        'verifyAppSignature',
        {'packageName': packageName},
      );
      return Map<String, dynamic>.from(result as Map);
    } on MissingPluginException {
      return {
        'packageName': packageName,
        'appName': packageName,
        'isVerified': false,
        'liveHash': null,
        'expectedHash': 'UNAVAILABLE',
        'verdict': 'PLATFORM_UNSUPPORTED',
      };
    } on PlatformException catch (e) {
      throw Exception('Verification failed: ${e.message}');
    }
  }
}
