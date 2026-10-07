"""
NIDS Dashboard - ML Predictor
Loads the trained model and provides a prediction function.
If model is unavailable, returns None so the caller falls back to rule-based.
"""

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "nids_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_names.joblib")

LABEL_MAP = {0: "NORMAL", 1: "SUSPICIOUS", 2: "HIGH_RISK"}

_model = None
_scaler = None
_feature_names = None
_ml_available = False


def load_model() -> bool:
    """
    Attempt to load the ML model from disk.
    Returns True if successful, False otherwise.
    Never raises — the application must work without ML.
    """
    global _model, _scaler, _feature_names, _ml_available
    try:
        import joblib
        if not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)):
            logger.info("ML model files not found. Using rule-based detection only.")
            _ml_available = False
            return False
        _model = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
        _feature_names = joblib.load(FEATURES_PATH)
        _ml_available = True
        logger.info("ML model loaded successfully.")
        return True
    except Exception as e:
        logger.warning("Failed to load ML model: %s. Using rule-based fallback.", e)
        _model = None
        _scaler = None
        _feature_names = None
        _ml_available = False
        return False


def is_ml_available() -> bool:
    """Return True if the ML model is loaded and ready."""
    return _ml_available


def predict(features: Dict[str, Any]) -> Optional[str]:
    """
    Predict traffic class from a features dict.
    Returns one of: 'NORMAL', 'SUSPICIOUS', 'HIGH_RISK'
    Returns None if ML is unavailable or prediction fails.
    """
    if not _ml_available or _model is None or _scaler is None or _feature_names is None:
        return None
    try:
        import numpy as np
        row = [float(features.get(f, 0) or 0) for f in _feature_names]
        X = np.array([row])
        X_scaled = _scaler.transform(X)
        pred = int(_model.predict(X_scaled)[0])
        return LABEL_MAP.get(pred, "NORMAL")
    except Exception as e:
        logger.warning("ML prediction error: %s", e)
        return None


def get_predictor():
    """
    Return the predict function if ML is available, else None.
    Use this as the ml_predictor argument to classifier.classify_record().
    """
    return predict if _ml_available else None
