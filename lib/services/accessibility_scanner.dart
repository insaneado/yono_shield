import 'package:flutter/services.dart';

class AccessibilityScanResult {
  final bool isThreat;
  final String? packageName;
  final String? appName;
  final String? serviceName;

  const AccessibilityScanResult({
    required this.isThreat,
    this.packageName,
    this.appName,
    this.serviceName,
  });

  factory AccessibilityScanResult.fromMap(Map<String, dynamic> map) {
    return AccessibilityScanResult(
      isThreat: map['isThreat'] as bool? ?? false,
      packageName: map['packageName'] as String?,
      appName: map['appName'] as String?,
      serviceName: map['serviceName'] as String?,
    );
  }
}

class AccessibilityScanner {
  static const MethodChannel _channel = MethodChannel(
    'kavach.security/accessibility',
  );

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
      return const AccessibilityScanResult(isThreat: false);
    } on PlatformException catch (error) {
      throw Exception('Accessibility scan failed: ${error.message}');
    }
  }
}
