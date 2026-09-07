"""
Module 1 - Log Generation / Collection
Generates synthetic authentication & application activity logs that mimic
what a real organization's auth/app logs look like (username, timestamp,
ip address, login status, resource accessed, downloads, session duration).

A handful of users are deliberately given anomalous behaviour patterns
(repeated failed logins, odd-hour access, unfamiliar IPs, download spikes,
bursts of activity) so the downstream detection pipeline has real signal
to find.
"""
import csv
import random
import zlib
from datetime import datetime, timedelta

RESOURCES = [
    "HR_Portal", "Finance_DB", "Customer_CRM", "Source_Code_Repo",
    "Payroll_System", "Email_Server", "File_Share", "Admin_Console",
    "Backup_Server", "VPN_Gateway",
]

NORMAL_USERS = [f"user{str(i).zfill(2)}" for i in range(1, 21)] + [
    "priya", "arjun", "meera", "santhosh", "ravi",
]

# Users that will be pushed into anomalous behaviour on specific days
ANOMALOUS_USERS = {
    "santhosh": "high_risk",   # failed logins + odd hour + new ip + downloads
    "user02":   "suspicious",  # multiple failed logins + downloads
    "user15":   "suspicious",  # unusual login time + new ip
}

KNOWN_IP_POOL = [f"192.168.1.{i}" for i in range(10, 40)]
# Built with a locally-seeded Random instance (not the module-level `random`
# used below) so this list is fixed at import time regardless of process,
# and doesn't consume/perturb the caller's seeded random stream.
_ip_rng = random.Random(1234)
UNFAMILIAR_IPS = [f"203.0.113.{i}" for i in range(1, 30)] + \
                  [f"45.33.{_ip_rng.randint(1, 254)}.{_ip_rng.randint(1, 254)}" for _ in range(10)]


def _random_time_on(day: datetime, business_hours=True):
    if business_hours:
        hour = random.randint(8, 18)
    else:
        hour = random.choice([0, 1, 2, 3, 4, 23])
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def _user_home_ip(username: str) -> str:
    """Deterministically pick a "home" IP per username without touching
    the module-level `random` state (Python's built-in hash() is also
    process-randomized by default, so crc32 is used for a stable seed
    across runs/processes)."""
    stable_seed = zlib.crc32(username.encode("utf-8"))
    return random.Random(stable_seed).choice(KNOWN_IP_POOL)


def generate_logs(output_path: str, days: int = 30, seed: int = 42):
    """Generate synthetic log CSV and write it to output_path."""
    random.seed(seed)
    rows = []
    end_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start_date = end_date - timedelta(days=days)

    for day_offset in range(days):
        day = start_date + timedelta(days=day_offset)

        for user in NORMAL_USERS:
            home_ip = _user_home_ip(user)
            profile = ANOMALOUS_USERS.get(user)

            # Decide if today is an "incident day" for anomalous users
            is_incident_day = False
            if profile and random.random() < 0.25:
                is_incident_day = True

            # ---- Regular daily login ----
            n_sessions = random.randint(1, 3)
            for _ in range(n_sessions):
                if profile and is_incident_day:
                    # Failed login attempts before eventual success
                    n_failed = random.randint(3, 6) if profile == "high_risk" else random.randint(2, 4)
                    for _ in range(n_failed):
                        ts = _random_time_on(day, business_hours=random.random() > 0.4)
                        rows.append([
                            ts.isoformat(), user, random.choice(UNFAMILIAR_IPS),
                            "LOGIN", "FAILED", "-", 0, 0,
                        ])
                    login_status = "SUCCESS"
                    ip_addr = random.choice(UNFAMILIAR_IPS)
                    business_hours = False
                else:
                    login_status = "SUCCESS" if random.random() > 0.03 else "FAILED"
                    ip_addr = home_ip
                    business_hours = True

                ts = _random_time_on(day, business_hours=business_hours)
                session_duration = round(random.uniform(5, 90), 1)
                rows.append([
                    ts.isoformat(), user, ip_addr, "LOGIN", login_status, "-", 0, session_duration,
                ])

                if login_status != "SUCCESS":
                    continue

                # ---- Activity within the session ----
                if profile and is_incident_day:
                    n_resource = random.randint(15, 30) if profile == "high_risk" else random.randint(8, 15)
                    n_downloads = random.randint(8, 20) if profile == "high_risk" else random.randint(5, 10)
                else:
                    n_resource = random.randint(1, 6)
                    n_downloads = random.randint(0, 2)

                activity_ts = ts
                for _ in range(n_resource):
                    activity_ts = activity_ts + timedelta(minutes=random.randint(1, 20))
                    rows.append([
                        activity_ts.isoformat(), user, ip_addr, "RESOURCE_ACCESS", "SUCCESS",
                        random.choice(RESOURCES), 0, 0,
                    ])

                for _ in range(n_downloads):
                    activity_ts = activity_ts + timedelta(minutes=random.randint(1, 15))
                    rows.append([
                        activity_ts.isoformat(), user, ip_addr, "DOWNLOAD", "SUCCESS",
                        random.choice(RESOURCES), random.randint(1, 5), 0,
                    ])

    rows.sort(key=lambda r: r[0])

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "username", "ip_address", "event_type", "login_status",
            "resource", "download_count", "session_duration_min",
        ])
        writer.writerows(rows)

    return output_path, len(rows)


if __name__ == "__main__":
    path, count = generate_logs("../logs/auth_activity_logs.csv")
    print(f"Generated {count} log rows -> {path}")
