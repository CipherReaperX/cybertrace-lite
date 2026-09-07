"""
Model evaluation - precision/recall/F1 of the detection pipeline against
the known ground truth baked into the synthetic data generator
(modules/log_generator.ANOMALOUS_USERS): those usernames are deliberately
given anomalous behaviour, everyone else is normal.

Only meaningful for synthetic runs. If none of the seeded usernames are
present in risk_scores (e.g. after a real-log upload), metrics degrade to
zeros rather than raising - the dashboard hides/annotates accordingly.
"""
import database as db
from modules.log_generator import ANOMALOUS_USERS

GROUND_TRUTH_ANOMALOUS = set(ANOMALOUS_USERS.keys())


def evaluate() -> dict:
    conn = db.get_connection()
    rows = conn.execute("SELECT username, classification FROM risk_scores").fetchall()
    conn.close()

    tp = fp = tn = fn = 0
    seeded_users_seen = set()
    for r in rows:
        actual_positive = r["username"] in GROUND_TRUTH_ANOMALOUS
        if actual_positive:
            seeded_users_seen.add(r["username"])
        predicted_positive = r["classification"] != "NORMAL"

        if actual_positive and predicted_positive:
            tp += 1
        elif actual_positive and not predicted_positive:
            fn += 1
        elif not actual_positive and predicted_positive:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "has_ground_truth": bool(seeded_users_seen),
        "ground_truth_users": sorted(seeded_users_seen),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "support": len(rows),
    }
