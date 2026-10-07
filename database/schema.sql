-- NIDS Dashboard SQLite Schema
-- Auto-initialized on first application start

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_name TEXT NOT NULL,
    filename TEXT,
    total_records INTEGER DEFAULT 0,
    valid_records INTEGER DEFAULT 0,
    invalid_records INTEGER DEFAULT 0,
    normal_count INTEGER DEFAULT 0,
    suspicious_count INTEGER DEFAULT 0,
    high_risk_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    detection_mode TEXT DEFAULT 'Rule-Based',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS traffic_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    timestamp TEXT,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    packet_count REAL DEFAULT 0,
    packet_size REAL DEFAULT 0,
    duration REAL DEFAULT 0,
    bytes_sent REAL DEFAULT 0,
    bytes_received REAL DEFAULT 0,
    connection_count REAL DEFAULT 0,
    packets_per_second REAL DEFAULT 0,
    bytes_per_second REAL DEFAULT 0,
    byte_ratio REAL DEFAULT 0,
    risk_score REAL DEFAULT 0,
    classification TEXT DEFAULT 'NORMAL',
    attack_type TEXT DEFAULT 'NONE',
    detection_reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    traffic_record_id INTEGER,
    timestamp TEXT,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    attack_type TEXT DEFAULT 'UNKNOWN',
    severity TEXT DEFAULT 'HIGH',
    risk_score REAL DEFAULT 0,
    description TEXT,
    status TEXT DEFAULT 'NEW',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (traffic_record_id) REFERENCES traffic_records(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_source_ip ON traffic_records(source_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_classification ON traffic_records(classification);
CREATE INDEX IF NOT EXISTS idx_traffic_created_at ON traffic_records(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
