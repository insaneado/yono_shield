// ============================================================================
// YONO SHIELD — AppScanResult Model
// ============================================================================
// Data model representing a single app from the Clone Radar package scan.
// Deserialized from the JSON map returned by the Kotlin PackageScannerService.
// ============================================================================

/// Risk level enumeration for scanned applications.
enum RiskLevel {
  safe,
  suspicious,
  dangerous;

  /// Parse a risk level string from the Kotlin layer.
  static RiskLevel fromString(String value) {
    switch (value.toUpperCase()) {
      case 'DANGEROUS':
        return RiskLevel.dangerous;
      case 'SUSPICIOUS':
        return RiskLevel.suspicious;
      case 'SAFE':
      default:
        return RiskLevel.safe;
    }
  }
}

/// Represents the scan result for a single installed application.
class AppScanResult {
  /// The Android package name (e.g., "com.sbi.fake")
  final String packageName;

  /// Human-readable app name (e.g., "Fake SBI")
  final String appName;

  /// The package name of the installer (e.g., "com.android.vending" for Play Store)
  final String installerSource;

  /// Whether the app was installed from a trusted source (Play Store, etc.)
  final bool isTrustedSource;

  /// Risk assessment: SAFE, SUSPICIOUS, or DANGEROUS
  final RiskLevel riskLevel;

  /// Human-readable explanation of why this risk level was assigned
  final String riskReason;

  const AppScanResult({
    required this.packageName,
    required this.appName,
    required this.installerSource,
    required this.isTrustedSource,
    required this.riskLevel,
    required this.riskReason,
  });

  /// Factory constructor to deserialize from the Map returned by Kotlin.
  factory AppScanResult.fromMap(Map<dynamic, dynamic> map) {
    return AppScanResult(
      packageName: map['packageName'] as String? ?? 'unknown',
      appName: map['appName'] as String? ?? 'Unknown App',
      installerSource: map['installerSource'] as String? ?? 'Unknown',
      isTrustedSource: map['isTrustedSource'] as bool? ?? false,
      riskLevel: RiskLevel.fromString(map['riskLevel'] as String? ?? 'SAFE'),
      riskReason: map['riskReason'] as String? ?? '',
    );
  }
}
