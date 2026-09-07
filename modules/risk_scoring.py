"""
Module 6 - Risk Scoring (Layer 1: rule-based detection)
Combines discrete security indicators into a 0-100 behavioural risk score,
per the scoring table:

    Failed login attempts        +20
    Unusual login time           +15
    New IP                       +20
    High resource access         +20
    Multiple downloads           +15
    Rapid activity               +10
    Sensitive resource access    +15   (Admin/Payroll/Finance/Backup, off-hours)
    Concurrent multi-IP session  +15   ("impossible travel" proxy)

Score is clipped to 100 even though the weights above can sum past it -
multiple simultaneous indicators still just mean "certainly high risk".

0-30   -> NORMAL
31-60  -> SUSPICIOUS
61-100 -> HIGH RISK
"""
import pandas as pd

INDICATOR_WEIGHTS = {
    "failed_login_flag": 20,
    "unusual_time_flag": 15,
    "new_ip_flag": 20,
    "high_resource_flag": 20,
    "multiple_downloads_flag": 15,
    "rapid_activity_flag": 10,
    "sensitive_access_flag": 15,
    "concurrent_session_flag": 15,
}

INDICATOR_LABELS = {
    "failed_login_flag": "Multiple failed logins",
    "unusual_time_flag": "Unusual login time",
    "new_ip_flag": "Login from a new / unfamiliar IP",
    "high_resource_flag": "Abnormally high resource access",
    "multiple_downloads_flag": "High volume file downloads",
    "rapid_activity_flag": "Rapid burst of activity",
    "sensitive_access_flag": "Sensitive resource accessed off-hours",
    "concurrent_session_flag": "Concurrent session from multiple IPs",
}


def classify(score: float) -> str:
    if score <= 30:
        return "NORMAL"
    elif score <= 60:
        return "SUSPICIOUS"
    else:
        return "HIGH RISK"


def compute_rule_score(row) -> tuple[int, list[str]]:
    score = 0
    triggered = []
    for flag_col, weight in INDICATOR_WEIGHTS.items():
        if bool(row.get(flag_col, False)):
            score += weight
            triggered.append(INDICATOR_LABELS[flag_col])
    return min(score, 100), triggered


def apply_rule_based_scoring(features_df: pd.DataFrame) -> pd.DataFrame:
    df = features_df.copy()
    scores = []
    reasons = []
    for _, row in df.iterrows():
        s, r = compute_rule_score(row)
        scores.append(s)
        reasons.append("; ".join(r))
    df["rule_score"] = scores
    df["rule_triggers"] = reasons
    return df
