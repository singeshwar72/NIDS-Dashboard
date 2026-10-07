"""
NIDS Dashboard - ML Model Training
Trains a RandomForest classifier on synthetic feature data.
The application works without this model (falls back to rule engine).

Usage:
    python ml/train_model.py
"""

import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import numpy as np

from detection.feature_engine import get_feature_names

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import classification_report
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.error("scikit-learn not available. Install it with: pip install scikit-learn")


MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "nids_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_names.joblib")

# Labels: 0=NORMAL, 1=SUSPICIOUS, 2=HIGH_RISK
LABEL_MAP = {0: "NORMAL", 1: "SUSPICIOUS", 2: "HIGH_RISK"}


def generate_synthetic_training_data(n_normal=800, n_suspicious=300, n_high_risk=200):
    """
    Generate deterministic synthetic training samples.
    Each sample represents realistic feature values for that class.
    Uses fixed random seed for reproducibility.
    """
    rng = np.random.RandomState(42)
    feature_names = get_feature_names()
    n_features = len(feature_names)

    samples = []
    labels = []

    # NORMAL traffic: low counts, balanced ratios, moderate rates
    for _ in range(n_normal):
        row = [
            rng.uniform(10, 200),      # packet_count
            rng.uniform(200, 1200),    # packet_size
            rng.uniform(0.5, 30),      # duration
            rng.uniform(1000, 500000), # bytes_sent
            rng.uniform(1000, 500000), # bytes_received
            rng.uniform(1, 10),        # connection_count
            rng.uniform(1, 50),        # packets_per_second
            rng.uniform(100, 50000),   # bytes_per_second
            rng.uniform(0.5, 3.0),     # byte_ratio
            rng.uniform(0.01, 0.5),    # connection_rate
            rng.uniform(0.8, 1.2),     # payload_ratio
            rng.choice([0, 1], p=[0.7, 0.3]),  # port_suspicious
            rng.choice([0, 1]),        # is_high_port_src
            rng.choice([0, 1], p=[0.6, 0.4]),  # is_privileged_dst
            rng.choice([1, 2, 4, 5, 6]),  # protocol_numeric
        ]
        samples.append(row)
        labels.append(0)

    # SUSPICIOUS traffic: moderate anomalies
    for _ in range(n_suspicious):
        row = [
            rng.uniform(100, 1000),     # packet_count
            rng.uniform(50, 500),       # packet_size (smaller)
            rng.uniform(0.1, 5),        # duration
            rng.uniform(100000, 2000000), # bytes_sent
            rng.uniform(100, 50000),    # bytes_received
            rng.uniform(10, 60),        # connection_count
            rng.uniform(50, 600),       # packets_per_second
            rng.uniform(50000, 600000), # bytes_per_second
            rng.uniform(5, 50),         # byte_ratio
            rng.uniform(0.5, 5),        # connection_rate
            rng.uniform(0.5, 2.0),      # payload_ratio
            rng.choice([0, 1], p=[0.4, 0.6]),  # port_suspicious
            rng.choice([0, 1]),         # is_high_port_src
            rng.choice([0, 1], p=[0.4, 0.6]),  # is_privileged_dst
            rng.choice([1, 2, 3, 8]),   # protocol_numeric
        ]
        samples.append(row)
        labels.append(1)

    # HIGH_RISK traffic: severe anomalies
    for _ in range(n_high_risk):
        row = [
            rng.uniform(500, 5000),      # packet_count
            rng.uniform(10, 64),         # packet_size (very small - scan probe)
            rng.uniform(0.01, 2),        # duration
            rng.uniform(1000000, 20000000), # bytes_sent
            rng.uniform(100, 10000),     # bytes_received
            rng.uniform(100, 500),       # connection_count
            rng.uniform(600, 5000),      # packets_per_second
            rng.uniform(500000, 5000000), # bytes_per_second
            rng.uniform(50, 500),        # byte_ratio
            rng.uniform(5, 50),          # connection_rate
            rng.uniform(0.1, 0.5),       # payload_ratio
            rng.choice([0, 1], p=[0.2, 0.8]),  # port_suspicious
            rng.choice([0, 1]),          # is_high_port_src
            rng.choice([0, 1], p=[0.3, 0.7]),  # is_privileged_dst
            rng.choice([1, 2, 3]),       # protocol_numeric
        ]
        samples.append(row)
        labels.append(2)

    X = np.array(samples)
    y = np.array(labels)
    return X, y, feature_names


def train_and_save() -> bool:
    """Train the RandomForest model and save to disk. Returns True on success."""
    if not SKLEARN_AVAILABLE:
        return False

    os.makedirs(MODEL_DIR, exist_ok=True)

    logger.info("Generating synthetic training data...")
    X, y, feature_names = generate_synthetic_training_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    logger.info("Training RandomForest classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    report = classification_report(y_test, y_pred, target_names=list(LABEL_MAP.values()))
    logger.info("Classification Report:\n%s", report)

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(feature_names, FEATURES_PATH)

    logger.info("Model saved to %s", MODEL_PATH)
    return True


if __name__ == "__main__":
    success = train_and_save()
    sys.exit(0 if success else 1)
