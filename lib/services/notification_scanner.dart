// ============================================================================
// KAVACH — notification_scanner.dart (Loophole 7: Notification Snooping)
// ============================================================================
//
// Flutter bridge to the native Kotlin notification listener scanner.
// Queries active notification listeners via Settings.Secure, then uses
// Installer Verification to flag sideloaded apps with notification access.
// ============================================================================

import 'package:flutter/services.dart';

/// Represents a single rogue notification listener.
class RogueListenerInfo {
  final String packageName;
  final String appName;
  final String installer;

  const RogueListenerInfo({
    required this.packageName,
    required this.appName,
    required this.installer,
  });

  factory RogueListenerInfo.fromMap(Map<String, dynamic> map) {
    return RogueListenerInfo(
      packageName: map['packageName'] as String? ?? '',
      appName: map['appName'] as String? ?? '',
      installer: map['installer'] as String? ?? 'UNKNOWN',
    );
  }
}

/// Result of a notification listener scan.
class NotificationScanResult {
  final bool isThreat;
  final String? packageName;
  final String? appName;
  final String? installer;
  final List<RogueListenerInfo> rogueListeners;

  const NotificationScanResult({
    required this.isThreat,
    this.packageName,
    this.appName,
    this.installer,
    this.rogueListeners = const [],
  });

  factory NotificationScanResult.fromMap(Map<String, dynamic> map) {
    final rawList = map['rogueListeners'] as List<dynamic>? ?? [];
    final rogueList = rawList
        .whereType<Map>()
        .map((e) => RogueListenerInfo.fromMap(Map<String, dynamic>.from(e)))
        .toList();

    return NotificationScanResult(
      isThreat: map['isThreat'] as bool? ?? false,
      packageName: map['packageName'] as String?,
      appName: map['appName'] as String?,
      installer: map['installer'] as String?,
      rogueListeners: rogueList,
    );
  }
}

/// Non-blocking Flutter bridge to the native notification listener scanner.
class NotificationScanner {
  static const MethodChannel _channel = MethodChannel(
    'kavach.security/notifications',
  );

  /// Queries the OS for active notification listeners and flags sideloaded ones.
  Future<NotificationScanResult> scanForSnoopers() async {
    try {
      final result = await _channel.invokeMethod<dynamic>(
        'checkRogueNotificationListeners',
      );

      if (result is Map) {
        return NotificationScanResult.fromMap(
          Map<String, dynamic>.from(result),
        );
      }

      return const NotificationScanResult(isThreat: false);
    } on MissingPluginException {
      return const NotificationScanResult(isThreat: false);
    } on PlatformException catch (error) {
      throw Exception('Notification scan failed: ${error.message}');
    }
  }
}
