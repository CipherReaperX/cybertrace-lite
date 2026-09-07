"""
CyberTrace-Lite - Flask Dashboard (Module 7)
Serves the security dashboard and JSON APIs that power it:
users / events / alerts / risk scores / anomalies / charts - plus
admin-only log upload, notification settings, and audit log views, and
a printable report / CSV export available to every logged-in role.
"""
import os
import sys
import csv
import io
import functools
from datetime import timedelta, datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, abort, Response
from werkzeug.security import check_password_hash
import database as db
import run_pipeline
from modules import log_ingestion, notifications, evaluation

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_PATH = os.path.join(BASE_DIR, "database", "secret_key.txt")
UPLOAD_TMP_PATH = os.path.join(BASE_DIR, "logs", "_upload_tmp.csv")


def _load_or_create_secret_key() -> str:
    """Persist a random secret key on disk so logged-in sessions survive
    a server restart instead of being invalidated every time."""
    os.makedirs(os.path.dirname(SECRET_KEY_PATH), exist_ok=True)
    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "r", encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key
    key = os.urandom(32).hex()
    with open(SECRET_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = _load_or_create_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,  # cap /logs/upload at 25MB
)


def login_required(view_func):
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "admin privileges required"}), 403
            abort(403)
        return view_func(*args, **kwargs)
    return wrapped


def ensure_db_ready():
    db.init_db()
    db.seed_default_admin()
    conn = db.get_connection()
    row = conn.execute("SELECT COUNT(*) AS c FROM risk_scores").fetchone()
    conn.close()
    if row["c"] == 0:
        run_pipeline.run()


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        conn = db.get_connection()
        row = conn.execute("SELECT * FROM auth_users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user"] = username
            session["role"] = row["role"]
            session.permanent = True
            db.log_audit(username, "login_success")
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)
        db.log_audit(username or "(unknown)", "login_failed")
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    if session.get("user"):
        db.log_audit(session["user"], "logout")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", current_user=session.get("user"), current_role=session.get("role"))


# ---------------------------------------------------------------- APIs ----

@app.route("/api/summary")
@login_required
def api_summary():
    conn = db.get_connection()
    users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    events = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
    high_risk_users = conn.execute(
        "SELECT COUNT(DISTINCT username) AS c FROM risk_scores WHERE classification = 'HIGH RISK'"
    ).fetchone()["c"]
    conn.close()
    return jsonify({
        "users": users,
        "events": events,
        "alerts": alerts,
        "high_risk_users": high_risk_users,
    })


@app.route("/api/risk_distribution")
@login_required
def api_risk_distribution():
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT classification, COUNT(*) AS c FROM risk_scores GROUP BY classification
    """).fetchall()
    conn.close()
    dist = {"NORMAL": 0, "SUSPICIOUS": 0, "HIGH RISK": 0}
    for r in rows:
        dist[r["classification"]] = r["c"]
    total = sum(dist.values()) or 1
    return jsonify({
        "counts": dist,
        "percentages": {k: round(v / total * 100, 1) for k, v in dist.items()},
    })


@app.route("/api/top_suspicious")
@login_required
def api_top_suspicious():
    limit = int(request.args.get("limit", 10))
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT username, MAX(final_score) AS max_score
        FROM risk_scores
        GROUP BY username
        ORDER BY max_score DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        result.append({
            "username": r["username"],
            "score": round(r["max_score"], 1),
            "classification": (
                "HIGH RISK" if r["max_score"] > 60 else "SUSPICIOUS" if r["max_score"] > 30 else "NORMAL"
            ),
        })
    return jsonify(result)


@app.route("/api/timeline")
@login_required
def api_timeline():
    conn = db.get_connection()
    events = conn.execute("""
        SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS c
        FROM events GROUP BY day ORDER BY day
    """).fetchall()
    anomalies = conn.execute("""
        SELECT date AS day, COUNT(*) AS c
        FROM risk_scores WHERE is_anomaly = 1 GROUP BY day ORDER BY day
    """).fetchall()
    conn.close()
    anomaly_map = {r["day"]: r["c"] for r in anomalies}
    return jsonify({
        "labels": [r["day"] for r in events],
        "event_counts": [r["c"] for r in events],
        "anomaly_counts": [anomaly_map.get(r["day"], 0) for r in events],
    })


@app.route("/api/alerts")
@login_required
def api_alerts():
    limit = int(request.args.get("limit", 25))
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT username, date, alert_type, message, severity, notified, created_at
        FROM alerts ORDER BY date DESC, id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users")
@login_required
def api_users():
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT u.username, u.first_seen, u.last_seen, u.total_events,
               MAX(rs.final_score) AS max_score
        FROM users u
        LEFT JOIN risk_scores rs ON rs.username = u.username
        GROUP BY u.username
        ORDER BY max_score DESC
    """).fetchall()
    conn.close()
    result = []
    for r in rows:
        score = r["max_score"] or 0
        result.append({
            "username": r["username"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "total_events": r["total_events"],
            "max_score": round(score, 1),
            "classification": "HIGH RISK" if score > 60 else "SUSPICIOUS" if score > 30 else "NORMAL",
        })
    return jsonify(result)


@app.route("/api/user/<username>")
@login_required
def api_user_detail(username):
    conn = db.get_connection()
    history = conn.execute("""
        SELECT * FROM risk_scores WHERE username = ? ORDER BY date
    """, (username,)).fetchall()
    events = conn.execute("""
        SELECT * FROM events WHERE username = ? ORDER BY timestamp DESC LIMIT 50
    """, (username,)).fetchall()
    conn.close()
    return jsonify({
        "history": [dict(r) for r in history],
        "recent_events": [dict(r) for r in events],
    })


@app.route("/api/model_eval")
@login_required
def api_model_eval():
    return jsonify(evaluation.evaluate())


@app.route("/api/risk_3d")
@login_required
def api_risk_3d():
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT username, date, rule_score, anomaly_score, final_score, classification
        FROM risk_scores
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/run_pipeline", methods=["POST"])
@login_required
@admin_required
def api_run_pipeline():
    payload = request.get_json(silent=True) or {}
    days = int(payload.get("days", 30))
    summary = run_pipeline.run(
        days=days, regenerate_logs=True, verbose=False,
        log_source="synthetic", triggered_by=session.get("user"),
    )
    return jsonify({"status": "ok", "summary": summary})


@app.route("/api/export/csv")
@login_required
def export_csv():
    conn = db.get_connection()
    rows = conn.execute("SELECT * FROM risk_scores ORDER BY date, username").fetchall()
    conn.close()
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        for r in rows:
            writer.writerow(dict(r))
    db.log_audit(session.get("user"), "export_csv", f"rows={len(rows)}")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cybertrace_risk_report.csv"},
    )


# ----------------------------------------------------------- Admin pages --

@app.route("/logs/upload", methods=["GET", "POST"])
@login_required
@admin_required
def upload_logs():
    result = None
    error = None
    if request.method == "POST":
        file = request.files.get("logfile")
        if not file or file.filename == "":
            error = "Choose a CSV file first."
        else:
            os.makedirs(os.path.dirname(UPLOAD_TMP_PATH), exist_ok=True)
            file.save(UPLOAD_TMP_PATH)
            try:
                summary = log_ingestion.validate_and_save(UPLOAD_TMP_PATH, run_pipeline.IMPORTED_LOG_FILE)
                pipeline_summary = run_pipeline.run(
                    log_source="uploaded", verbose=False, triggered_by=session.get("user"),
                )
                db.log_audit(
                    session.get("user"), "log_upload",
                    f"rows={summary['rows']}, users={summary['distinct_users']}, file={file.filename}",
                )
                result = {**summary, "pipeline": pipeline_summary}
            except log_ingestion.LogValidationError as e:
                error = str(e)
            finally:
                if os.path.exists(UPLOAD_TMP_PATH):
                    os.remove(UPLOAD_TMP_PATH)
    return render_template(
        "upload_logs.html", result=result, error=error,
        required_columns=log_ingestion.REQUIRED_COLUMNS,
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
@admin_required
def settings_page():
    message = None
    if request.method == "POST":
        cfg = notifications.load_config()
        cfg["smtp"]["enabled"] = "smtp_enabled" in request.form
        cfg["smtp"]["host"] = request.form.get("smtp_host", "").strip()
        cfg["smtp"]["port"] = int(request.form.get("smtp_port") or 587)
        cfg["smtp"]["username"] = request.form.get("smtp_username", "").strip()
        new_password = request.form.get("smtp_password", "")
        if new_password:
            cfg["smtp"]["password"] = new_password
        cfg["smtp"]["from_addr"] = request.form.get("smtp_from", "").strip()
        cfg["smtp"]["to_addr"] = request.form.get("smtp_to", "").strip()
        cfg["smtp"]["use_tls"] = "smtp_tls" in request.form

        cfg["webhook"]["enabled"] = "webhook_enabled" in request.form
        cfg["webhook"]["url"] = request.form.get("webhook_url", "").strip()

        notifications.save_config(cfg)
        db.log_audit(session.get("user"), "settings_change", "updated notification config")
        message = "Settings saved."
    cfg = notifications.load_config()
    return render_template("settings.html", cfg=cfg, message=message)


@app.route("/audit")
@login_required
@admin_required
def audit_log_page():
    conn = db.get_connection()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return render_template("audit_log.html", rows=[dict(r) for r in rows])


# ------------------------------------------------------------- Reporting --

@app.route("/report")
@login_required
def report():
    conn = db.get_connection()
    summary = {
        "users": conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"],
        "events": conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"],
        "alerts": conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"],
    }
    dist_rows = conn.execute(
        "SELECT classification, COUNT(*) AS c FROM risk_scores GROUP BY classification"
    ).fetchall()
    distribution = {"NORMAL": 0, "SUSPICIOUS": 0, "HIGH RISK": 0}
    for r in dist_rows:
        distribution[r["classification"]] = r["c"]
    top_users = conn.execute("""
        SELECT username, MAX(final_score) AS max_score
        FROM risk_scores GROUP BY username ORDER BY max_score DESC LIMIT 15
    """).fetchall()
    alerts = conn.execute("""
        SELECT username, date, message, severity FROM alerts ORDER BY date DESC, id DESC LIMIT 50
    """).fetchall()
    conn.close()
    db.log_audit(session.get("user"), "report_view")
    return render_template(
        "report.html", summary=summary, distribution=distribution,
        top_users=[dict(r) for r in top_users], alerts=[dict(r) for r in alerts],
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )


if __name__ == "__main__":
    import logging

    log_path = os.path.join(BASE_DIR, "logs", "server.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logging.basicConfig(
        filename=log_path, level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    # Local runs default to loopback-only (matches the auto-start-at-login
    # setup described in the README). In a container, 127.0.0.1 is only
    # reachable from inside that container's own network namespace, so
    # Docker/Fly deploys set CT_HOST=0.0.0.0 (see Dockerfile) to bind on
    # all interfaces and be reachable through the published port.
    host = os.environ.get("CT_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))

    try:
        ensure_db_ready()
        from waitress import serve
        logging.info(f"Starting CyberTrace-Lite on http://{host}:{port}")
        print(f"CyberTrace-Lite running at http://{host}:{port}")
        serve(app, host=host, port=port)
    except Exception:
        logging.exception("CyberTrace-Lite server crashed")
        raise
