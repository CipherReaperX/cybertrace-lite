"""
Module 4 - Behavioral Analysis
Establishes each user's "normal" activity baseline (typical IPs, average
resource access, average downloads, average events/day) and flags the
daily feature rows that deviate from that personal baseline
(e.g. a brand-new IP address, resource access far above the user's own
average).
"""
import pandas as pd


def build_user_baselines(features_df: pd.DataFrame) -> pd.DataFrame:
    """Compute a per-user historical baseline (mean/std) for the core
    behavioural metrics, using all rows available for that user.
    """
    baseline = features_df.groupby("username").agg(
        avg_resource_access=("resource_access_count", "mean"),
        std_resource_access=("resource_access_count", "std"),
        avg_downloads=("download_count", "mean"),
        std_downloads=("download_count", "std"),
        avg_total_events=("total_events", "mean"),
        std_total_events=("total_events", "std"),
    ).fillna(0.0)
    return baseline.reset_index()


def _known_ips_before(ip_history: dict, username: str, date, ip_list_str: str):
    """Return the set of IPs seen for a user strictly before `date`, and
    update the running history with today's IPs.
    """
    known = ip_history.setdefault(username, set())
    today_ips = set(x for x in ip_list_str.split(",") if x)
    new_ips_today = today_ips - known
    known |= today_ips
    return new_ips_today


def apply_behavior_analysis(features_df: pd.DataFrame) -> pd.DataFrame:
    """Enrich the per-user/day feature rows with baseline deviation flags:
    - new_ip_flag: at least one IP not seen before for this user
    - high_resource_flag: resource access significantly above personal average
    - rapid_activity_flag: bursty activity above personal average
    """
    df = features_df.copy().sort_values(["username", "date"]).reset_index(drop=True)
    baseline = build_user_baselines(df).set_index("username")

    ip_history = {}
    new_ip_flags = []
    high_resource_flags = []
    rapid_activity_flags = []

    for _, row in df.iterrows():
        username = row["username"]
        new_ips = _known_ips_before(ip_history, username, row["date"], row["ip_list"])
        new_ip_flags.append(bool(new_ips))

        b = baseline.loc[username] if username in baseline.index else None
        if b is not None and b["avg_resource_access"] > 0:
            threshold = b["avg_resource_access"] + max(2 * b["std_resource_access"], 3)
            high_resource_flags.append(bool(row["resource_access_count"] > threshold))
        else:
            high_resource_flags.append(bool(row["resource_access_count"] > 10))

        if b is not None and b["avg_total_events"] > 0:
            threshold_events = b["avg_total_events"] + max(2 * b["std_total_events"], 5)
            rapid_activity_flags.append(bool(row["rapid_event_count"] >= 5 and row["total_events"] > threshold_events))
        else:
            rapid_activity_flags.append(bool(row["rapid_event_count"] >= 5))

    df["new_ip_flag"] = new_ip_flags
    df["high_resource_flag"] = high_resource_flags
    df["rapid_activity_flag"] = rapid_activity_flags
    df["unusual_time_flag"] = df["unusual_time_events"] > 0
    df["multiple_downloads_flag"] = df["download_count"] >= 5
    df["failed_login_flag"] = df["failed_logins"] >= 3

    # Sensitive resource (Admin_Console, Payroll_System, ...) touched outside
    # normal hours - more specific than the general "unusual time" flag.
    df["sensitive_access_flag"] = (df["sensitive_resource_count"] > 0) & df["unusual_time_flag"]

    # Different IPs used within a suspiciously tight time window on the same day.
    df["concurrent_session_flag"] = df["concurrent_ip_overlap"].astype(bool)

    return df
