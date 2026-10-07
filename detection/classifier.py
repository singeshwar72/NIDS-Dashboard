"""
NIDS Dashboard - Detection Classifier
Orchestrates: features -> rules -> risk -> classification.
Optionally uses ML model if available; falls back to rule-based engine gracefully.
"""

import logging
from typing import Any, Dict

from detection.feature_engine import extract_features
from detection.rule_engine import run_rules
from detection.risk_engine import calculate_risk

logger = logging.getLogger(__name__)


def classify_record(sanitized_record: Dict[str, Any], ml_predictor=None) -> Dict[str, Any]:
    """
    Full classification pipeline for a single sanitized traffic record.

    Pipeline:
        sanitized_record
            -> feature extraction
            -> rule-based detection
            -> risk scoring
            -> [optional ML prediction]
            -> final result dict

    Args:
        sanitized_record: Validated traffic record dict
        ml_predictor: Optional ML predict function; if None, rule-based only.

    Returns:
        Complete enriched record dict including risk_score, classification,
        attack_type, detection_reason, and detection_mode.
    """
    # Step 1: Extract features
    features = extract_features(sanitized_record)

    # Step 2: Rule-based detection
    detection_result = run_rules(features)

    # Step 3: Risk scoring
    risk_result = calculate_risk(detection_result, features)

    # Step 4: Optional ML prediction
    ml_classification = None
    detection_mode = "Rule-Based"

    if ml_predictor is not None:
        try:
            ml_classification = ml_predictor(features)
            detection_mode = "Rule-Based + ML"

            # ML can elevate risk but not reduce it (conservative approach)
            ml_label = str(ml_classification).upper()
            if ml_label == "HIGH_RISK" and risk_result["risk_score"] < 60:
                risk_result["risk_score"] = max(risk_result["risk_score"], 62.0)
                risk_result["classification"] = "HIGH RISK"
                risk_result["reasons"].append("ML model flagged as HIGH_RISK")
            elif ml_label == "SUSPICIOUS" and risk_result["risk_score"] < 40:
                risk_result["risk_score"] = max(risk_result["risk_score"], 42.0)
                risk_result["classification"] = "SUSPICIOUS"
                risk_result["reasons"].append("ML model flagged as SUSPICIOUS")
        except Exception as e:
            logger.warning("ML prediction failed, using rule-based only: %s", e)
            detection_mode = "Rule-Based"
            ml_classification = None

    # Build final enriched record
    result = {
        **sanitized_record,
        **features,
        "risk_score": risk_result["risk_score"],
        "classification": risk_result["classification"],
        "attack_type": risk_result["attack_type"],
        "detection_reason": " | ".join(risk_result["reasons"][:5]),  # cap at 5 reasons
        "detection_mode": detection_mode,
        "ml_classification": str(ml_classification) if ml_classification else None,
        "rule_triggers": [r.rule_name for r in detection_result.triggered_rules],
        "full_reasons": risk_result["reasons"],
    }
    return result
