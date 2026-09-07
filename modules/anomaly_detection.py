"""
Module 5 - Anomaly Detection (Layer 2: unsupervised anomaly detection)
Runs TWO independent unsupervised outlier detectors over the behavioural
feature matrix - Isolation Forest and Local Outlier Factor - and blends
them into a single anomaly score. Using two models that work on different
principles (global partitioning vs. local density) instead of one gives a
more robust "second opinion" than either alone, and lets the report
describe a genuine ensemble:

    "The proposed system combines rule-based risk scoring with an
     ensemble of unsupervised anomaly detectors (Isolation Forest +
     Local Outlier Factor)."
"""
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

ANOMALY_FEATURES = [
    "failed_logins",
    "unusual_time_events",
    "distinct_ip_count",
    "resource_access_count",
    "download_count",
    "session_duration_avg",
    "total_events",
    "rapid_event_count",
    "sensitive_resource_count",
]

FEATURE_LABELS = {
    "failed_logins": "Failed logins",
    "unusual_time_events": "Unusual-time activity",
    "distinct_ip_count": "Distinct IP addresses",
    "resource_access_count": "Resource access volume",
    "download_count": "Downloads",
    "session_duration_avg": "Avg session duration",
    "total_events": "Total events",
    "rapid_event_count": "Rapid activity bursts",
    "sensitive_resource_count": "Sensitive resource access",
}


def _top_features_shap(iforest, X_scaled: np.ndarray, cols: list[str], top_n: int = 3) -> list[list[dict]]:
    """Per-row top contributing features via SHAP TreeExplainer over the
    fitted Isolation Forest. Returns [] for a row if SHAP itself fails
    (version incompatibility etc.) so callers can fall back."""
    import shap

    explainer = shap.TreeExplainer(iforest)
    shap_values = explainer.shap_values(X_scaled)
    shap_values = np.asarray(shap_values)

    out = []
    for row in shap_values:
        order = np.argsort(-np.abs(row))[:top_n]
        out.append([
            {
                "feature": FEATURE_LABELS.get(cols[i], cols[i]),
                "impact": round(float(row[i]), 3),
            }
            for i in order
        ])
    return out


def _top_features_zscore(X: np.ndarray, cols: list[str], top_n: int = 3) -> list[list[dict]]:
    """Fallback explanation: for each row, the features furthest (in
    absolute z-score) from the population mean."""
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std < 1e-9] = 1.0
    z = (X - mean) / std

    out = []
    for row in z:
        order = np.argsort(-np.abs(row))[:top_n]
        out.append([
            {
                "feature": FEATURE_LABELS.get(cols[i], cols[i]),
                "impact": round(float(row[i]), 3),
            }
            for i in order
        ])
    return out


def _normalize_higher_is_more_anomalous(raw: np.ndarray) -> np.ndarray:
    min_v, max_v = raw.min(), raw.max()
    if max_v - min_v > 1e-9:
        return (raw - min_v) / (max_v - min_v) * 100
    return np.zeros_like(raw)


def apply_anomaly_detection(features_df: pd.DataFrame, contamination: float = 0.1, random_state: int = 42) -> pd.DataFrame:
    df = features_df.copy()

    if len(df) < 10:
        # Not enough data to fit a meaningful model
        df["iforest_score"] = 0.0
        df["lof_score"] = 0.0
        df["anomaly_score"] = 0.0
        df["is_anomaly"] = False
        df["shap_top_features"] = [json.dumps([]) for _ in range(len(df))]
        return df

    cols = [c for c in ANOMALY_FEATURES if c in df.columns]
    X = df[cols].fillna(0.0).to_numpy()
    X_scaled = StandardScaler().fit_transform(X)

    # --- Detector 1: Isolation Forest (global, partition-based) ---
    iforest = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
    )
    iforest.fit(X_scaled)
    iforest_raw = -iforest.decision_function(X_scaled)  # higher = more anomalous
    iforest_pred = iforest.predict(X_scaled)  # -1 = anomaly

    # --- Detector 2: Local Outlier Factor (local density based) ---
    n_neighbors = max(2, min(20, len(df) - 1))
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=contamination)
    lof_pred = lof.fit_predict(X_scaled)  # -1 = anomaly
    lof_raw = -lof.negative_outlier_factor_  # higher = more anomalous

    iforest_score = _normalize_higher_is_more_anomalous(iforest_raw)
    lof_score = _normalize_higher_is_more_anomalous(lof_raw)

    df["iforest_score"] = np.round(iforest_score, 1)
    df["lof_score"] = np.round(lof_score, 1)
    df["anomaly_score"] = np.round((iforest_score + lof_score) / 2, 1)
    df["is_anomaly"] = (iforest_pred == -1) | (lof_pred == -1)

    # --- Explainability: which features drove each row's anomaly score ---
    try:
        top_features = _top_features_shap(iforest, X_scaled, cols)
    except Exception:
        top_features = _top_features_zscore(X_scaled, cols)
    df["shap_top_features"] = [json.dumps(tf) for tf in top_features]

    return df
