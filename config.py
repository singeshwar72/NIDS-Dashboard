"""
NIDS Dashboard Configuration
Loads settings from environment variables with safe defaults.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""

    # Flask
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "nids-dev-secret-change-in-production")
    DEBUG: bool = os.environ.get("DEBUG", "False").lower() == "true"

    # Database
    DATABASE_PATH: str = os.environ.get("DATABASE_PATH", "nids.db")

    # Upload
    UPLOAD_FOLDER: str = os.environ.get("UPLOAD_FOLDER", "uploads")
    MAX_CONTENT_LENGTH: int = int(os.environ.get("MAX_UPLOAD_MB", "10")) * 1024 * 1024  # 10 MB
    ALLOWED_EXTENSIONS: set = {"csv"}

    # Demo dataset
    DEMO_DATASET_PATH: str = os.path.join("data", "sample_traffic.csv")

    # Detection thresholds
    HIGH_CONN_THRESHOLD: int = int(os.environ.get("HIGH_CONN_THRESHOLD", "50"))
    HIGH_PACKET_RATE_THRESHOLD: float = float(os.environ.get("HIGH_PACKET_RATE_THRESHOLD", "1000.0"))
    HIGH_BYTES_THRESHOLD: int = int(os.environ.get("HIGH_BYTES_THRESHOLD", "10000000"))

    # Risk score bands
    RISK_NORMAL_MAX: int = 19
    RISK_LOW_MAX: int = 39
    RISK_SUSPICIOUS_MAX: int = 59
    RISK_HIGH_MAX: int = 79
    # >= 80 -> CRITICAL

    # Pagination
    PAGE_SIZE: int = int(os.environ.get("PAGE_SIZE", "50"))

    # ML
    ML_MODEL_PATH: str = os.path.join("ml", "model", "nids_model.joblib")
    ML_SCALER_PATH: str = os.path.join("ml", "model", "scaler.joblib")
    ML_FEATURES_PATH: str = os.path.join("ml", "model", "feature_names.joblib")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


def get_config() -> Config:
    env = os.environ.get("FLASK_ENV", "development").lower()
    return DevelopmentConfig() if env == "development" else ProductionConfig()
