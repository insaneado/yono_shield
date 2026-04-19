import 'dart:async';
import 'dart:convert';

import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'telemetry_db.dart';

const String _telemetryEndpoint = 'http://10.0.2.2:8080/api/telemetry';
const Duration _telemetryTimeout = Duration(seconds: 5);

/// Queues telemetry locally, then attempts a best-effort cloud sync.
Future<void> reportFraudSilently(String badPackage, String threatType) async {
  try {
    await SyncManager.instance.initialize();
    await TelemetryDatabase.instance.insertThreat(
      packageName: badPackage,
      threatType: threatType,
      timestamp: DateTime.now().toIso8601String(),
    );
    unawaited(SyncManager.instance.attemptSync());
  } catch (error, stackTrace) {
    debugPrint('KAVACH telemetry queue error: $error\n$stackTrace');
  }
}

/// Connectivity-aware store-and-forward sync engine.
class SyncManager {
  SyncManager._();

  static final SyncManager instance = SyncManager._();

  final Connectivity _connectivity = Connectivity();

  bool _initialized = false;
  bool _isSyncing = false;

  Future<void> initialize() async {
    if (_initialized) {
      return;
    }

    await TelemetryDatabase.instance.initialize();
    _connectivity.onConnectivityChanged.listen((results) {
      if (_hasActiveConnection(results)) {
        unawaited(attemptSync());
      }
    });
    _initialized = true;
  }

  Future<void> attemptSync() async {
    await initialize();

    if (_isSyncing) {
      return;
    }

    final connectivityResults = await _connectivity.checkConnectivity();
    if (!_hasActiveConnection(connectivityResults)) {
      return;
    }

    _isSyncing = true;
    try {
      final pendingThreats =
          await TelemetryDatabase.instance.getPendingThreats();
      for (final threat in pendingThreats) {
        try {
          final response = await http
              .post(
                Uri.parse(_telemetryEndpoint),
                headers: const {'Content-Type': 'application/json'},
                body: jsonEncode(threat.toApiPayload()),
              )
              .timeout(_telemetryTimeout);

          if (response.statusCode == 200) {
            await TelemetryDatabase.instance.markThreatSynced(threat.id);
          }
        } on TimeoutException catch (error) {
          debugPrint('KAVACH telemetry sync timeout for ${threat.id}: $error');
        } on http.ClientException catch (error) {
          debugPrint(
            'KAVACH telemetry sync client error for ${threat.id}: $error',
          );
        } catch (error) {
          debugPrint('KAVACH telemetry sync failed for ${threat.id}: $error');
        }
      }
    } finally {
      _isSyncing = false;
    }
  }

  bool _hasActiveConnection(List<ConnectivityResult> results) {
    return results.any((result) => result != ConnectivityResult.none);
  }
}
