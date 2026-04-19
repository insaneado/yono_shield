import 'package:flutter/services.dart';

/// Represents a single rogue accessibility service detected on the device.
class RogueServiceInfo {
  final String packageName;
  final String appName;
  final String serviceName;
  final String installer;

  const RogueServiceInfo({
    required this.packageName,
    required this.appName,
    required this.serviceName,
    required this.installer,
  });

  factory RogueServiceInfo.fromMap(Map<String, dynamic> map) {
    return RogueServiceInfo(
      packageName: map['packageName'] as String? ?? '',
      appName: map['appName'] as String? ?? '',
      serviceName: map['serviceName'] as String? ?? '',
      installer: map['installer'] as String? ?? 'UNKNOWN',
    );
  }
}

/// Result of a KAVACH accessibility hijack scan.
///
/// Uses Installer Verification: only sideloaded apps (not installed via the
/// Google Play Store or other trusted stores) that hold active Accessibility
/// permissions are flagged as threats.
class AccessibilityScanResult {
  final bool isThreat;
  final String? packageName;
  final String? appName;
  final String? serviceName;
  final String? installer;
  final List<RogueServiceInfo> rogueServices;

  const AccessibilityScanResult({
    required this.isThreat,
    this.packageName,
    this.appName,
    this.serviceName,
    this.installer,
    this.rogueServices = const [],
  });

  factory AccessibilityScanResult.fromMap(Map<String, dynamic> map) {
    final rawList = map['rogueServices'] as List<dynamic>? ?? [];
    final rogueList = rawList
        .whereType<Map>()
        .map((e) => RogueServiceInfo.fromMap(Map<String, dynamic>.from(e)))
        .toList();

    return AccessibilityScanResult(
      isThreat: map['isThreat'] as bool? ?? false,
      packageName: map['packageName'] as String?,
      appName: map['appName'] as String?,
      serviceName: map['serviceName'] as String?,
      installer: map['installer'] as String?,
      rogueServices: rogueList,
    );
  }
}

/// Non-blocking Flutter bridge to the native KAVACH accessibility scanner.
///
/// Invokes the Kotlin-side `checkRogueAccessibility` method over the
/// `kavach.security/accessibility` MethodChannel.
class AccessibilityScanner {
  static const MethodChannel _channel = MethodChannel(
    'kavach.security/accessibility',
  );

  /// Queries the OS for active Accessibility Services, checks each one's
  /// install source via PackageManager, and flags sideloaded apps.
  ///
  /// Returns [AccessibilityScanResult] with `isThreat == true` if at least
  /// one sideloaded service is active.  The UI frame is never blocked.
  Future<AccessibilityScanResult> scanForHijack() async {
    try {
      final result = await _channel.invokeMethod<dynamic>(
        'checkRogueAccessibility',
      );

      if (result is Map) {
        return AccessibilityScanResult.fromMap(
          Map<String, dynamic>.from(result),
        );
      }

      return const AccessibilityScanResult(isThreat: false);
    } on MissingPluginException {
      // Running on a platform without the native channel (e.g. iOS, desktop).
      return const AccessibilityScanResult(isThreat: false);
    } on PlatformException catch (error) {
      throw Exception('Accessibility scan failed: ${error.message}');
    }
  }
}
