"""
Module 1b - Log Ingestion (real logs)
Validates an uploaded CSV against the same schema the synthetic generator
produces, so the rest of the pipeline (Preprocessing -> ... -> Risk
Scoring) can consume real, organization-provided logs exactly like it
consumes the synthetic ones - no other module needs to change.

Expected columns:
    timestamp, username, ip_address, event_type, login_status, resource,
    download_count, session_duration_min

This targets CyberTrace-Lite's own internal schema rather than arbitrary
Windows Event Log / syslog exports; convert real log exports into this
CSV shape before uploading (see README).
"""
import os
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "username", "ip_address", "event_type", "login_status",
    "resource", "download_count", "session_duration_min",
]


class LogValidationError(Exception):
    pass


def validate_and_save(uploaded_file_path: str, destination_path: str) -> dict:
    """Validate an uploaded CSV file at `uploaded_file_path`. Raises
    LogValidationError with a human-readable reason on failure. On
    success, writes a copy to `destination_path` and returns a summary.
    """
    try:
        df = pd.read_csv(uploaded_file_path)
    except Exception as e:
        raise LogValidationError(f"Could not parse the file as CSV: {e}")

    if df.empty:
        raise LogValidationError("The uploaded file has no rows.")

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise LogValidationError(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Expected columns: {', '.join(REQUIRED_COLUMNS)}"
        )

    parsed_ts = pd.to_datetime(df["timestamp"], errors="coerce")
    bad_ts = int(parsed_ts.isna().sum())
    if bad_ts == len(df):
        raise LogValidationError("No rows had a parseable 'timestamp' value (expected ISO format).")

    if df["username"].isna().all():
        raise LogValidationError("The 'username' column is empty for every row.")

    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    df.to_csv(destination_path, index=False)

    return {
        "rows": int(len(df)),
        "unparseable_timestamps": bad_ts,
        "distinct_users": int(df["username"].nunique()),
        "saved_to": destination_path,
    }
