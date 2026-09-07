"""
Module 3 - Feature Extraction
Extracts per user / per day behavioural features from the cleaned log
dataframe: username, timestamp window, ip addresses used, login status
counts, resources accessed, downloads, session duration, activity
frequency.
"""
import pandas as pd

# Business hours considered "normal" login time
NORMAL_HOUR_START = 7
NORMAL_HOUR_END = 21

# Resources whose access carries extra risk regardless of volume
SENSITIVE_RESOURCES = {"Admin_Console", "Payroll_System", "Finance_DB", "Backup_Server"}

# Two events from *different* IPs closer together than this look like a
# proxy for "impossible travel" / a shared or stolen credential being used
# from two places near-simultaneously.
CONCURRENT_WINDOW_SECONDS = 900  # 15 minutes


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate raw events into one row per (username, date) with the
    behavioural indicators needed for rule based scoring and anomaly
    detection.
    """
    records = []

    for (username, date), grp in df.groupby(["username", "date"]):
        logins = grp[grp["event_type"] == "LOGIN"]
        failed_logins = int((logins["login_status"] == "FAILED").sum())
        successful_logins = int((logins["login_status"] == "SUCCESS").sum())

        unusual_time_events = int(
            (~grp["hour"].between(NORMAL_HOUR_START, NORMAL_HOUR_END)).sum()
        )

        distinct_ips = sorted(grp["ip_address"].unique().tolist())

        resource_access_count = int((grp["event_type"] == "RESOURCE_ACCESS").sum())
        download_events = grp[grp["event_type"] == "DOWNLOAD"]
        download_count = int(download_events.shape[0])

        session_duration_avg = float(grp.loc[grp["session_duration_min"] > 0, "session_duration_min"].mean() or 0.0)

        total_events = int(grp.shape[0])

        sorted_grp = grp.sort_values("timestamp")

        # Rapid activity: events packed into short bursts (<= 2 min apart)
        gaps = sorted_grp["timestamp"].diff().dt.total_seconds()
        rapid_event_count = int((gaps <= 120).sum())

        # Concurrent-IP overlap: a different IP shows up sooner than
        # CONCURRENT_WINDOW_SECONDS after the previous event - a lightweight
        # proxy for "impossible travel" without needing real IP geolocation.
        ip_changed = sorted_grp["ip_address"] != sorted_grp["ip_address"].shift(1)
        concurrent_ip_overlap = bool(((gaps <= CONCURRENT_WINDOW_SECONDS) & ip_changed & gaps.notna()).any())

        sensitive_resource_count = int(grp["resource"].isin(SENSITIVE_RESOURCES).sum())

        records.append({
            "username": username,
            "date": date,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "unusual_time_events": unusual_time_events,
            "distinct_ip_count": len(distinct_ips),
            "ip_list": ",".join(distinct_ips),
            "resource_access_count": resource_access_count,
            "download_count": download_count,
            "session_duration_avg": round(session_duration_avg, 2),
            "total_events": total_events,
            "rapid_event_count": rapid_event_count,
            "sensitive_resource_count": sensitive_resource_count,
            "concurrent_ip_overlap": concurrent_ip_overlap,
        })

    features_df = pd.DataFrame.from_records(records)
    features_df = features_df.sort_values(["username", "date"]).reset_index(drop=True)
    return features_df
