# NIDS Security Operations Dashboard

## B.Tech CSE Cybersecurity Project — ICT Academy

---

## Abstract

The Network Intrusion Detection System (NIDS) Security Operations Dashboard is a full-stack cybersecurity monitoring application built with Python, Flask, SQLite, and Chart.js. It analyzes supplied network traffic data through a multi-stage detection pipeline: validation → feature extraction → rule-based detection → risk scoring → alert generation → live dashboard. The system supports optional machine learning (Random Forest) for enhanced classification while maintaining full rule-based fallback functionality.

---

## Problem Statement

Modern networks generate enormous volumes of traffic. Security Operations Centers (SOCs) need automated tools to identify suspicious patterns, score risk, and present actionable intelligence. This project demonstrates a complete intrusion detection workflow, from raw CSV traffic data to a professional SOC dashboard with real-time statistics, alert management, and detailed analysis reports.

---

## Objectives

1. Parse and validate real-format network traffic CSV files
2. Extract meaningful features (packets/sec, byte ratios, connection rates)
3. Apply rule-based detection for known anomaly patterns
4. Calculate deterministic risk scores (0–100) with band classification
5. Generate and manage alerts for high-risk and critical traffic
6. Present all statistics through a live, database-backed SOC dashboard
7. Optionally enhance detection with a trained Random Forest ML model
8. Demonstrate secure coding practices throughout

---

## Features

- **SOC Dashboard**: Live KPI cards, 5 Chart.js visualizations, all data from SQLite
- **Traffic Monitor**: Filterable, sortable, paginated traffic table with detail view
- **Alert Management**: Full lifecycle (New → Acknowledged → Resolved)
- **Intrusion Analysis**: Per-record page with risk score, reasons, recommendations
- **Dataset Upload**: Drag-and-drop CSV with validation summary
- **Detection History**: Scan session log with delete (with confirmation)
- **Demo Dataset**: Synthetic traffic covering Normal → Critical scenarios
- **Demo Monitoring**: Simulated live refresh mode
- **ML Support**: Random Forest model (optional, auto-trained)
- **Rule Engine**: 8 detection rules with severity and explanation
- **Risk Engine**: Deterministic 0–100 scoring, 5 classification bands
- **Security**: Parameterized SQL, input validation, security headers, no shell execution

---

## System Architecture

```
CSV / Demo Traffic Dataset
         ↓
   Data Validation        (detection/validators.py)
         ↓
   Feature Extraction     (detection/feature_engine.py)
         ↓
  Rule-Based Detection    (detection/rule_engine.py)
         ↓
  Optional ML Detection   (ml/predict.py)
         ↓
     Risk Scoring         (detection/risk_engine.py)
         ↓
    Classification        (detection/classifier.py)
         ↓
   Alert Generation       (services/alert_service.py)
         ↓
   SQLite Database        (database/database.py)
         ↓
    Flask REST API        (app.py)
         ↓
  JavaScript / Chart.js   (static/js/)
         ↓
   SOC Dashboard          (templates/)
```

---

## Workflow

1. User uploads CSV or clicks **Load Demo Dataset**
2. `traffic_service.process_csv_file()` validates each row
3. Valid rows go through `classifier.classify_record()`:
   - Features extracted by `feature_engine.extract_features()`
   - Rules evaluated by `rule_engine.run_rules()`
   - Risk calculated by `risk_engine.calculate_risk()`
   - ML prediction applied if model is available
4. Results stored in `traffic_records` and `alerts` tables
5. Dashboard fetches stats from `/api/dashboard-stats`
6. Charts fetch from `/api/chart/*` endpoints
7. All numbers reflect actual database state — never hardcoded

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Database | SQLite (via built-in `sqlite3`) |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn (Random Forest), Joblib |
| Frontend | HTML5, CSS3, JavaScript (ES6+) |
| UI Framework | Bootstrap 5 |
| Charting | Chart.js 4 |
| Testing | Pytest |
| Config | python-dotenv |

---

## Folder Structure

```
nids-dashboard/
├── app.py                      # Flask application factory, all routes
├── config.py                   # Configuration (env vars + defaults)
├── requirements.txt
├── README.md
├── .env.example
│
├── database/
│   ├── __init__.py
│   ├── database.py             # DatabaseManager (all CRUD, parameterized SQL)
│   └── schema.sql              # Table definitions + indexes
│
├── detection/
│   ├── __init__.py
│   ├── validators.py           # IP, port, protocol, CSV row validation
│   ├── feature_engine.py       # Feature computation (pkt/s, byte ratio…)
│   ├── rule_engine.py          # 8 rule functions + DetectionResult
│   ├── risk_engine.py          # Deterministic 0–100 risk scorer
│   └── classifier.py           # Orchestrates full detection pipeline
│
├── ml/
│   ├── __init__.py
│   ├── train_model.py          # Train and save RandomForest model
│   ├── predict.py              # Load model, expose predict()
│   └── model/                  # Saved .joblib files (generated)
│
├── services/
│   ├── __init__.py
│   ├── traffic_service.py      # CSV ingestion + full pipeline execution
│   └── alert_service.py        # Alert list, update, summary
│
├── data/
│   └── sample_traffic.csv      # 120-row synthetic demo dataset
│
├── templates/
│   ├── base.html               # Layout (sidebar, topbar, toast)
│   ├── dashboard.html          # KPI cards + 5 charts
│   ├── traffic.html            # Traffic monitor table
│   ├── alerts.html             # Alert management table
│   ├── analysis.html           # Per-record intrusion analysis
│   ├── upload.html             # CSV upload page
│   ├── history.html            # Scan session history
│   └── about.html              # Project info, architecture, methodology
│
├── static/
│   ├── css/style.css           # Dark SOC theme
│   └── js/
│       ├── dashboard.js        # KPI + chart loading, demo controls
│       ├── traffic.js          # Table, filters, pagination, quick view
│       ├── alerts.js           # Alert table, status updates, detail modal
│       ├── analysis.js         # Risk meter animation
│       └── upload.js           # Drop zone, file upload, result display
│
└── tests/
    ├── test_validators.py
    ├── test_detection.py
    ├── test_risk_engine.py
    ├── test_database.py
    └── test_api.py
```

---

## Database Schema

### `scan_sessions`
| Column | Type | Description |
|---|---|---|
| id | INTEGER PK | Auto-increment |
| session_name | TEXT | Human-readable session label |
| filename | TEXT | Source CSV filename |
| total_records | INTEGER | Rows processed |
| valid_records | INTEGER | Rows successfully classified |
| invalid_records | INTEGER | Rows rejected by validation |
| normal_count | INTEGER | NORMAL classifications |
| suspicious_count | INTEGER | SUSPICIOUS classifications |
| high_risk_count | INTEGER | HIGH RISK classifications |
| critical_count | INTEGER | CRITICAL classifications |
| detection_mode | TEXT | Rule-Based or Rule-Based + ML |
| created_at | DATETIME | Session creation time |

### `traffic_records`
Stores all validated, classified traffic records including all raw fields plus computed features (packets_per_second, bytes_per_second, byte_ratio), risk_score, classification, attack_type, detection_reason.

### `alerts`
| Column | Type | Description |
|---|---|---|
| id | INTEGER PK | Auto-increment |
| session_id | INTEGER FK | Parent session |
| traffic_record_id | INTEGER FK | Source record |
| timestamp | TEXT | Event time |
| source_ip | TEXT | Attacker/suspicious IP |
| destination_ip | TEXT | Target IP |
| attack_type | TEXT | RECONNAISSANCE, FLOOD, etc. |
| severity | TEXT | HIGH or CRITICAL |
| risk_score | REAL | 0–100 |
| description | TEXT | Detection reason text |
| status | TEXT | NEW / ACKNOWLEDGED / RESOLVED |
| created_at | DATETIME | Alert creation time |
| updated_at | DATETIME | Last status change time |

---

## Detection Methodology

### Rule-Based Detection (8 Rules)

| Rule | Trigger | Severity | Attack Type |
|---|---|---|---|
| HIGH_CONNECTION_FREQUENCY | connection_count ≥ 50 | HIGH | RECONNAISSANCE |
| HIGH_CONNECTION_FREQUENCY | connection_count ≥ 200 | CRITICAL | RECONNAISSANCE |
| HIGH_PACKET_RATE | pkt/s ≥ 500 | HIGH | FLOOD |
| HIGH_PACKET_RATE | pkt/s ≥ 2000 | CRITICAL | FLOOD |
| LARGE_TRAFFIC_VOLUME | total bytes ≥ 5 MB | HIGH | EXFILTRATION |
| LARGE_TRAFFIC_VOLUME | total bytes ≥ 50 MB | CRITICAL | EXFILTRATION |
| ABNORMAL_BYTE_RATIO | sent/recv ≥ 100 | HIGH | EXFILTRATION |
| ABNORMAL_BYTE_RATIO | sent/recv ≤ 0.01 | MEDIUM | FLOOD |
| SUSPICIOUS_DESTINATION_PORT | dst port in known list | MEDIUM | SUSPICIOUS_PORT |
| FAST_CONNECTION_RATE | conn/s ≥ 10 | HIGH | PORT_SCAN |
| SMALL_PACKET_ANOMALY | size < 64 AND count > 100 | MEDIUM | SCANNING |
| HIGH_BANDWIDTH | bytes/s ≥ 1 MB/s | HIGH | DDOS |
| HIGH_BANDWIDTH | bytes/s ≥ 10 MB/s | CRITICAL | DDOS |

### Risk Score Formula

```
base_score = sum(triggered_rule.score_contribution)
+ feature_amplifiers (small bonuses for near-threshold values)
final_score = clamp(base_score, 0, 100)
```

Risk bands: 0–19 NORMAL | 20–39 LOW RISK | 40–59 SUSPICIOUS | 60–79 HIGH RISK | 80–100 CRITICAL

---

## ML Methodology

- **Algorithm**: Random Forest (100 trees, max_depth=10)
- **Features**: 15 engineered features (packet rates, byte ratios, port indicators, protocol encoding)
- **Classes**: 0=NORMAL, 1=SUSPICIOUS, 2=HIGH_RISK
- **Training data**: Synthetic samples generated with realistic feature distributions per class
- **Conservative fusion**: ML can only raise risk score, never lower it
- **Fallback**: Application functions fully without the model

Train the model:
```
python ml/train_model.py
```

---

## Installation

### Windows — Step by Step

```cmd
# 1. Clone or extract the project
cd nids-dashboard

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Copy environment file
copy .env.example .env

# 6. (Optional) Train ML model
python ml/train_model.py

# 7. Start the application
python app.py
```

Open your browser at: **http://127.0.0.1:5000**

The database is automatically initialized on first start.

---

## Running the Application

```cmd
python app.py
```

The application starts on `http://127.0.0.1:5000`.

To run on all interfaces (e.g., LAN access):
```cmd
# Edit app.py last line: host="0.0.0.0"
python app.py
```

---

## Loading Demo Data

1. Open **http://127.0.0.1:5000/dashboard**
2. Click **Load Demo Dataset**
3. The system processes `data/sample_traffic.csv` through the full pipeline
4. Dashboard statistics update automatically
5. Click **Traffic Monitor** to view classified records
6. Click **Alerts** to see generated alerts
7. Click any traffic record's analysis icon for the Intrusion Analysis page

---

## Uploading Custom Datasets

1. Open **http://127.0.0.1:5000/upload**
2. Drag and drop or browse for your CSV file
3. Required columns: `source_ip`, `destination_ip`
4. Optional columns: `timestamp`, `source_port`, `destination_port`, `protocol`, `packet_count`, `packet_size`, `duration`, `bytes_sent`, `bytes_received`, `connection_count`
5. Click **Upload & Analyze**
6. View processing summary (valid/invalid rows, classification counts, alert count)

---

## Running Tests

```cmd
# Activate virtual environment first
venv\Scripts\activate

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_validators.py -v

# Run with coverage report
pytest tests/ --tb=short
```

---

## API Documentation

### Page Routes
| Method | Path | Description |
|---|---|---|
| GET | / | Redirect to /dashboard |
| GET | /dashboard | SOC Dashboard |
| GET | /traffic | Traffic Monitor |
| GET | /alerts | Alert Management |
| GET | /analysis/\<id\> | Intrusion Analysis detail |
| GET | /upload | Dataset Upload |
| GET | /history | Detection History |
| GET | /about | About & Documentation |

### API Endpoints
| Method | Path | Description |
|---|---|---|
| GET | /api/dashboard-stats | KPI summary from DB |
| GET | /api/chart/classification | Classification pie chart data |
| GET | /api/chart/attack-types | Attack type bar chart data |
| GET | /api/chart/alerts-over-time | 7-day alert trend line data |
| GET | /api/chart/risk-distribution | Risk band histogram data |
| GET | /api/chart/top-source-ips | Top 10 source IPs by connections |
| GET | /api/traffic | Paginated traffic records (filters: classification, protocol, search) |
| GET | /api/traffic/\<id\> | Single traffic record detail |
| GET | /api/alerts | Paginated alerts (filters: status, severity, search) |
| PATCH | /api/alerts/\<id\> | Update alert status (body: {"status": "ACKNOWLEDGED"}) |
| GET | /api/history | Paginated scan sessions |
| DELETE | /api/history/\<id\> | Delete scan session (CASCADE) |
| POST | /api/upload | Upload and process CSV file |
| POST | /api/demo | Load synthetic demo dataset |
| POST | /api/analyze | Analyze a single record (JSON body) |

---

## Security Considerations

1. **SQL Injection**: All queries use parameterized statements; no string concatenation
2. **File Upload**: Extension validation, size limit (10 MB), filename sanitization via `werkzeug.utils.secure_filename`
3. **Input Validation**: All uploaded data validated before any processing
4. **Error Handling**: Stack traces never exposed to users; logged server-side
5. **Security Headers**: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection on every response
6. **No Shell Execution**: No `subprocess`, `os.system`, `eval()`, or `exec()`
7. **Secrets**: SECRET_KEY loaded from environment variables only
8. **Output Escaping**: All user-derived data escaped in JS with `esc()` function

---

## Limitations

1. No real-time packet capture (pcap); analyzes supplied CSV data only
2. ML model trained on synthetic data — accuracy on real traffic will vary
3. No authentication/authorization (single-user development tool)
4. SQLite not suitable for very large production deployments (use PostgreSQL)
5. No email/SMS alerting (dashboard display only)
6. Rule thresholds are configurable but require restart to take effect

---

## Future Scope

1. Real-time packet capture using `scapy` or `pyshark`
2. User authentication with role-based access (analyst, admin)
3. Email/Slack alert notifications
4. PostgreSQL backend for production scalability
5. PCAP file upload support
6. IP geolocation integration
7. Threat intelligence feed integration (e.g., AbuseIPDB)
8. Deep learning models (LSTM for sequential traffic analysis)
9. Kubernetes deployment with horizontal scaling
10. REST API authentication (JWT tokens)

---

## Viva Questions and Answers

**Q1: What is an Intrusion Detection System?**
A: An IDS monitors network traffic and system events for suspicious patterns. This project implements a Network IDS (NIDS) that analyzes traffic records for anomalies.

**Q2: What is the difference between NIDS and HIDS?**
A: NIDS monitors network traffic; HIDS monitors host system events (processes, file changes). This is a NIDS.

**Q3: How does the risk score work?**
A: Each triggered rule contributes a score (e.g., HIGH_PACKET_RATE = 18 points). Feature amplifiers add small bonuses. The total is clamped to 0–100. This is fully deterministic — same input always gives same score.

**Q4: Why does the application work without the ML model?**
A: The ML model is optional. `ml/predict.py` returns `None` if the model is unavailable, and `classifier.classify_record()` checks `ml_predictor is None` before calling it. The rule engine always runs independently.

**Q5: How is SQL injection prevented?**
A: All SQL queries in `database.py` use parameterized statements with `?` placeholders. User input is never concatenated into SQL strings.

**Q6: What attack types can the system detect?**
A: RECONNAISSANCE (high connection counts), FLOOD (high packet rates), EXFILTRATION (large volumes, asymmetric ratios), PORT_SCAN (fast connection rates), SCANNING (small-packet anomalies), DDOS (high bandwidth), SUSPICIOUS_PORT (known attack-pattern ports).

**Q7: What is feature engineering?**
A: Transforming raw data into numerical features suitable for analysis. Examples: computing packets-per-second from packet_count and duration, or byte_ratio from bytes_sent and bytes_received.

**Q8: What is Random Forest?**
A: An ensemble ML algorithm that builds multiple decision trees and aggregates their predictions. It's robust, handles high-dimensional data, and provides feature importance scores.

**Q9: Why is the ML conservative (can only raise risk)?**
A: To prevent false negatives. If the rule engine detects a threat but ML says NORMAL, we prefer to keep the alert. Security tools should err on the side of caution.

**Q10: How does the demo monitoring work?**
A: It sets a JavaScript `setInterval()` that calls `refreshAll()` every 5 seconds. It does NOT generate attacks or capture real network traffic — it simply re-reads the database statistics periodically.

---

## Credits

Built as a B.Tech Computer Science & Engineering cybersecurity project for ICT Academy demonstration.

**Technology Purpose Summary**:
- Python: Backend logic, data processing, ML
- Flask: REST API and server-side rendering
- SQLite: Persistent data storage (traffic records, alerts, sessions)
- Pandas: CSV parsing and DataFrame manipulation
- Scikit-learn: Random Forest classification
- Bootstrap 5: Responsive, professional UI framework
- Chart.js: Interactive data visualizations
- Pytest: Automated test suite
