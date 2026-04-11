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

// ignore_for_file: unintended_html_in_doc_comment

import 'package:flutter/services.dart';

class SecurityBridge {
  static final SecurityBridge _instance = SecurityBridge._internal();
  factory SecurityBridge() => _instance;
  SecurityBridge._internal();

  static const MethodChannel _channel = MethodChannel(
    'com.yonoshield.security/bridge',
  );

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
  /// The native bridge now short-circuits with a plain String verdict for:
  ///   1. Root detection → "ROOTED_DEVICE"
  ///   2. Trojan audit   → "TROJAN_DETECTED_<AppName>"
  ///
  /// If both gates pass, Android returns the existing signature-verification
  /// result map. This wrapper normalizes either shape into one Dart map so the
  /// UI can render a single verdict model.
  Future<Map<String, dynamic>> verifyAppSecurity(String packageName) async {
    try {
      final result = await _channel.invokeMethod('verifyAppSecurity', {
        'packageName': packageName,
      });
      return _normalizeSecurityResult(result, packageName);
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

  Map<String, dynamic> _normalizeSecurityResult(
    dynamic result,
    String packageName,
  ) {
    if (result is Map) {
      return Map<String, dynamic>.from(result);
    }

    final verdict = result?.toString() ?? 'UNKNOWN';

    if (verdict == 'ROOTED_DEVICE') {
      return {
        'verdict': verdict,
        'packageName': packageName,
        'isRooted': true,
        'trojanApp': null,
        'liveHash': null,
        'expectedHash': 'UNAVAILABLE',
        'message':
            'Device OS compromised. Root access was detected and YONO remains locked.',
      };
    }

    if (verdict.startsWith('TROJAN_DETECTED_')) {
      final trojanApp = verdict.split('TROJAN_DETECTED_').last.trim();
      final safeTrojanApp = trojanApp.isEmpty ? 'Unknown app' : trojanApp;

      return {
        'verdict': verdict,
        'packageName': packageName,
        'isRooted': false,
        'trojanApp': safeTrojanApp,
        'liveHash': null,
        'expectedHash': 'UNAVAILABLE',
        'message':
            "'$safeTrojanApp' has malicious screen-reading permissions. Uninstall immediately to unlock YONO.",
      };
    }

    return {
      'verdict': verdict,
      'packageName': packageName,
      'isRooted': false,
      'trojanApp': null,
      'liveHash': null,
      'expectedHash': 'UNAVAILABLE',
      'message': 'Unknown security verdict returned by the native bridge.',
    };
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
        return result.map((e) => Map<String, dynamic>.from(e as Map)).toList();
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
      final result = await _channel.invokeMethod('getAppSignatureHash', {
        'packageName': packageName,
      });
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
      final result = await _channel.invokeMethod('verifyAppSignature', {
        'packageName': packageName,
      });
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

  Future<void> uninstallApp(String packageName) async {
    try {
      await _channel.invokeMethod('uninstallApp', {'packageName': packageName});
    } on MissingPluginException {
      return;
    } on PlatformException catch (e) {
      throw Exception('Uninstall failed: ${e.message}');
    }
  }
}
