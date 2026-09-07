"""
Module 2 - Log Preprocessing
Cleans and standardizes raw log records: parses timestamps, fixes types,
drops malformed rows, normalizes text fields.
"""
import pandas as pd


REQUIRED_COLUMNS = [
    "timestamp", "username", "ip_address", "event_type", "login_status",
    "resource", "download_count", "session_duration_min",
]


def load_raw_logs(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    return df


def preprocess_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Clean & standardize the raw log dataframe."""
    df = df.copy()

    # Ensure required columns exist
    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            raise ValueError(f"Missing required log column: {col}")

    # Drop fully empty / malformed rows
    df = df.dropna(subset=["timestamp", "username", "event_type"])

    # Standardize text fields
    df["username"] = df["username"].astype(str).str.strip().str.lower()
    df["ip_address"] = df["ip_address"].astype(str).str.strip()
    df["event_type"] = df["event_type"].astype(str).str.strip().str.upper()
    df["login_status"] = df["login_status"].astype(str).str.strip().str.upper()
    df["resource"] = df["resource"].fillna("-").astype(str).str.strip()

    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    # Numeric fields
    df["download_count"] = pd.to_numeric(df["download_count"], errors="coerce").fillna(0).astype(int)
    df["session_duration_min"] = pd.to_numeric(df["session_duration_min"], errors="coerce").fillna(0.0)

    # Derived time fields used across the pipeline
    df["date"] = df["timestamp"].dt.date
    df["hour"] = df["timestamp"].dt.hour

    df = df.sort_values("timestamp").reset_index(drop=True)
    return df
