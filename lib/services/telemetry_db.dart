import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:sqflite/sqflite.dart';

/// Immutable model for one queued telemetry record.
class QueuedThreat {
  final int id;
  final String packageName;
  final String threatType;
  final String timestamp;
  final String status;

  const QueuedThreat({
    required this.id,
    required this.packageName,
    required this.threatType,
    required this.timestamp,
    required this.status,
  });

  factory QueuedThreat.fromMap(Map<String, Object?> map) {
    return QueuedThreat(
      id: map['id'] as int,
      packageName: map['package_name'] as String? ?? '',
      threatType: map['threat_type'] as String? ?? '',
      timestamp: map['timestamp'] as String? ?? '',
      status: map['status'] as String? ?? 'pending',
    );
  }

  Map<String, Object?> toApiPayload() {
    return {
      'device_id': 'hashed_mock_id_123',
      'package_name': packageName,
      'threat_type': threatType,
      'timestamp': timestamp,
    };
  }
}

/// Local SQLite vault for store-and-forward telemetry.
class TelemetryDatabase {
  TelemetryDatabase._();

  static final TelemetryDatabase instance = TelemetryDatabase._();

  static const _databaseName = 'kavach_telemetry.db';
  static const _databaseVersion = 1;
  static const _tableName = 'threat_queue';

  Database? _database;
  Future<Database>? _openDatabaseFuture;

  /// Ensures the database is initialized before the first write attempt.
  Future<void> initialize() async {
    await database;
  }

  Future<Database> get database async {
    if (_database != null) {
      return _database!;
    }

    if (_openDatabaseFuture != null) {
      return _openDatabaseFuture!;
    }

    _openDatabaseFuture = _open();
    _database = await _openDatabaseFuture!;
    return _database!;
  }

  Future<int> insertThreat({
    required String packageName,
    required String threatType,
    required String timestamp,
  }) async {
    final db = await database;
    return db.insert(_tableName, {
      'package_name': packageName,
      'threat_type': threatType,
      'timestamp': timestamp,
      'status': 'pending',
    });
  }

  Future<List<QueuedThreat>> getPendingThreats() async {
    final db = await database;
    final rows = await db.query(
      _tableName,
      where: 'status = ?',
      whereArgs: const ['pending'],
      orderBy: 'id ASC',
    );

    return rows.map(QueuedThreat.fromMap).toList();
  }

  Future<void> markThreatSynced(int id) async {
    final db = await database;
    await db.update(
      _tableName,
      {'status': 'synced'},
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  Future<Database> _open() async {
    final appSupportDir = await getApplicationSupportDirectory();
    final dbPath = p.join(appSupportDir.path, _databaseName);

    return openDatabase(
      dbPath,
      version: _databaseVersion,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE $_tableName (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
          )
        ''');
      },
    );
  }
}
