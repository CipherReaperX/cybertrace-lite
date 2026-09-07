"""
CyberTrace-Lite end-to-end pipeline runner.

    LOG FILES -> Log Collection -> Log Preprocessing -> Feature Extraction
    -> Behavioral Analysis -> Anomaly Detection -> Risk Score Engine
    -> SQLite (consumed by the Flask Dashboard) -> Alerting

Run directly to (re)generate synthetic logs, analyze them, and populate
the SQLite database used by app.py:

    python run_pipeline.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.log_generator import generate_logs
from modules.preprocessing import load_raw_logs, preprocess_logs
from modules.feature_extraction import extract_features
from modules.behavior_analysis import apply_behavior_analysis
from modules.risk_scoring import apply_rule_based_scoring, classify
from modules.anomaly_detection import apply_anomaly_detection
from modules import notifications
import database as db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
SYNTHETIC_LOG_FILE = os.path.join(LOG_DIR, "auth_activity_logs.csv")
IMPORTED_LOG_FILE = os.path.join(LOG_DIR, "imported_logs.csv")

# Final score blends the deterministic rule score with the unsupervised
# anomaly score so neither layer alone decides the outcome.
RULE_WEIGHT = 0.7
ANOMALY_WEIGHT = 0.3


def run(days: int = 30, regenerate_logs: bool = True, verbose: bool = True,
        log_source: str = "synthetic", triggered_by: str = None):
    """Run the full pipeline.

    log_source: "synthetic" (generate/re-use synthetic logs) or
                "uploaded" (consume logs/imported_logs.csv, produced by
                the /logs/upload route via modules/log_ingestion.py).
    triggered_by: username to attribute this run to in the audit log
                  (None for CLI / unattended runs).
    """
    t0 = time.time()
    os.makedirs(LOG_DIR, exist_ok=True)

    # ---- Module 1: Log Collection ----
    if log_source == "uploaded":
        if not os.path.exists(IMPORTED_LOG_FILE):
            raise FileNotFoundError(
                f"No uploaded log file found at {IMPORTED_LOG_FILE}. Upload one via /logs/upload first."
            )
        log_file = IMPORTED_LOG_FILE
        count = sum(1 for _ in open(log_file, encoding="utf-8")) - 1
        if verbose:
            print(f"[1/7] Log Collection      -> using uploaded {count} rows at {log_file}")
    else:
        log_file = SYNTHETIC_LOG_FILE
        if regenerate_logs or not os.path.exists(log_file):
            path, count = generate_logs(log_file, days=days)
            if verbose:
                print(f"[1/7] Log Collection      -> generated {count} rows at {path}")
        else:
            count = sum(1 for _ in open(log_file, encoding="utf-8")) - 1
            if verbose:
                print(f"[1/7] Log Collection      -> using existing {count} rows at {log_file}")

    # ---- Module 2: Log Preprocessing ----
    raw_df = load_raw_logs(log_file)
    clean_df = preprocess_logs(raw_df)
    if verbose:
        print(f"[2/7] Log Preprocessing   -> {len(clean_df)} clean events")

    # ---- Module 3: Feature Extraction ----
    features_df = extract_features(clean_df)
    if verbose:
        print(f"[3/7] Feature Extraction  -> {len(features_df)} user-day feature rows")

    # ---- Module 4: Behavioral Analysis ----
    behavior_df = apply_behavior_analysis(features_df)
    if verbose:
        print(f"[4/7] Behavioral Analysis -> baselines built, deviation flags computed")

    # ---- Module 5: Anomaly Detection (Isolation Forest + LOF ensemble) ----
    anomaly_df = apply_anomaly_detection(behavior_df)
    n_anom = int(anomaly_df["is_anomaly"].sum())
    if verbose:
        print(f"[5/7] Anomaly Detection   -> ensemble flagged {n_anom} anomalous rows")

    # ---- Module 6: Risk Scoring (rule-based + blended final score) ----
    scored_df = apply_rule_based_scoring(anomaly_df)
    scored_df["final_score"] = (
        RULE_WEIGHT * scored_df["rule_score"] + ANOMALY_WEIGHT * scored_df["anomaly_score"]
    ).clip(0, 100).round(1)
    scored_df["classification"] = scored_df["final_score"].apply(classify)
    if verbose:
        counts = scored_df["classification"].value_counts().to_dict()
        print(f"[6/7] Risk Scoring        -> {counts}")

    # ---- Persist everything to SQLite for the dashboard ----
    db.reset_db()
    conn = db.get_connection()
    cur = conn.cursor()

    # users
    user_stats = clean_df.groupby("username").agg(
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        total_events=("timestamp", "count"),
    ).reset_index()
    for _, r in user_stats.iterrows():
        cur.execute(
            "INSERT OR REPLACE INTO users (username, first_seen, last_seen, total_events) VALUES (?, ?, ?, ?)",
            (r["username"], str(r["first_seen"]), str(r["last_seen"]), int(r["total_events"])),
        )

    # events (bulk insert raw cleaned events)
    event_rows = clean_df[[
        "timestamp", "username", "ip_address", "event_type", "login_status",
        "resource", "download_count", "session_duration_min",
    ]].copy()
    event_rows["timestamp"] = event_rows["timestamp"].astype(str)
    cur.executemany(
        """INSERT INTO events (timestamp, username, ip_address, event_type, login_status,
                                resource, download_count, session_duration_min)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        event_rows.itertuples(index=False, name=None),
    )

    # risk_scores + alerts
    alert_rows = []  # tuples for bulk insert into `alerts`
    high_risk_new_incidents = []  # dicts, only ones not already notified

    already_notified = {
        (r["username"], r["date"], r["alert_type"])
        for r in conn.execute("SELECT username, date, alert_type FROM notified_incidents").fetchall()
    }

    for _, r in scored_df.iterrows():
        cur.execute(
            """INSERT OR REPLACE INTO risk_scores
               (username, date, failed_logins, unusual_time_events, distinct_ip_count,
                resource_access_count, download_count, rapid_event_count,
                sensitive_resource_count, concurrent_ip_overlap, rule_score,
                rule_triggers, anomaly_score, is_anomaly, final_score, classification,
                shap_explanation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                r["username"], str(r["date"]), int(r["failed_logins"]), int(r["unusual_time_events"]),
                int(r["distinct_ip_count"]), int(r["resource_access_count"]), int(r["download_count"]),
                int(r["rapid_event_count"]), int(r["sensitive_resource_count"]), int(bool(r["concurrent_ip_overlap"])),
                int(r["rule_score"]), r["rule_triggers"],
                float(r["anomaly_score"]), int(bool(r["is_anomaly"])), float(r["final_score"]), r["classification"],
                r.get("shap_top_features", "[]"),
            ),
        )

        row_alert_defs = []
        if r["classification"] in ("SUSPICIOUS", "HIGH RISK") and r["rule_triggers"]:
            severity = "HIGH" if r["classification"] == "HIGH RISK" else "MEDIUM"
            for reason in r["rule_triggers"].split("; "):
                row_alert_defs.append((reason, f"{r['username']} - {reason}", severity))
        if r["is_anomaly"]:
            row_alert_defs.append((
                "Statistical anomaly",
                f"{r['username']} - Behavior flagged as statistical anomaly (Isolation Forest + LOF ensemble)",
                "HIGH" if r["classification"] == "HIGH RISK" else "MEDIUM",
            ))

        for alert_type, message, severity in row_alert_defs:
            key = (r["username"], str(r["date"]), alert_type)
            is_new_high = severity == "HIGH" and key not in already_notified
            alert_rows.append((r["username"], str(r["date"]), alert_type, message, severity, int(not is_new_high)))
            if is_new_high:
                high_risk_new_incidents.append({
                    "username": r["username"], "date": str(r["date"]),
                    "alert_type": alert_type, "message": message,
                })
                already_notified.add(key)  # avoid duplicate within this same run too

    cur.executemany(
        "INSERT INTO alerts (username, date, alert_type, message, severity, notified) VALUES (?, ?, ?, ?, ?, ?)",
        alert_rows,
    )

    conn.commit()

    # ---- Alerting: notify once per new HIGH-severity incident ----
    notify_result = notifications.notify(high_risk_new_incidents)
    if high_risk_new_incidents:
        conn.executemany(
            "INSERT OR IGNORE INTO notified_incidents (username, date, alert_type) VALUES (?, ?, ?)",
            [(i["username"], i["date"], i["alert_type"]) for i in high_risk_new_incidents],
        )
        conn.commit()

    conn.close()

    db.log_audit(
        triggered_by, "run_pipeline",
        f"log_source={log_source}, users={len(user_stats)}, events={len(event_rows)}, "
        f"alerts={len(alert_rows)}, new_notifications={len(high_risk_new_incidents)}",
    )

    if verbose:
        n_alerts = len(alert_rows)
        print(f"[7/7] Persisted to SQLite -> {len(user_stats)} users, {len(event_rows)} events, "
              f"{len(scored_df)} risk rows, {n_alerts} alerts")
        if high_risk_new_incidents:
            print(f"      Notifications -> {len(high_risk_new_incidents)} new high-risk incident(s), "
                  f"email_sent={notify_result['email_sent']}, webhook_sent={notify_result['webhook_sent']}, "
                  f"errors={notify_result['errors']}")
        print(f"Done in {time.time() - t0:.2f}s. Database: {db.DB_PATH}")

    return {
        "users": len(user_stats),
        "events": len(event_rows),
        "risk_rows": len(scored_df),
        "alerts": len(alert_rows),
        "new_notifications": len(high_risk_new_incidents),
    }


if __name__ == "__main__":
    run()
