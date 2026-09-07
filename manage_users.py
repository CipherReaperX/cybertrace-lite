"""
CLI to manage CyberTrace-Lite dashboard login accounts (separate from the
monitored users tracked by the analytics pipeline).

Usage:
    python manage_users.py add <username> <password> [admin|viewer]
    python manage_users.py reset-password <username> <new_password>
    python manage_users.py set-role <username> <admin|viewer>
    python manage_users.py delete <username>
    python manage_users.py list
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from werkzeug.security import generate_password_hash
import database as db

VALID_ROLES = ("admin", "viewer")


def add_user(username: str, password: str, role: str = "viewer"):
    role = role.lower()
    if role not in VALID_ROLES:
        print(f"Invalid role '{role}'. Use one of: {', '.join(VALID_ROLES)}")
        return
    db.init_db()
    conn = db.get_connection()
    try:
        conn.execute(
            "INSERT INTO auth_users (username, password_hash, role) VALUES (?, ?, ?)",
            (username.strip().lower(), generate_password_hash(password), role),
        )
        conn.commit()
        print(f"Created login account '{username}' with role '{role}'.")
    except Exception as e:
        print(f"Failed to create '{username}': {e}")
    finally:
        conn.close()


def reset_password(username: str, new_password: str):
    db.init_db()
    conn = db.get_connection()
    cur = conn.execute(
        "UPDATE auth_users SET password_hash = ? WHERE username = ?",
        (generate_password_hash(new_password), username.strip().lower()),
    )
    conn.commit()
    if cur.rowcount == 0:
        print(f"No such user '{username}'. Use 'add' to create it.")
    else:
        print(f"Password updated for '{username}'.")
    conn.close()


def set_role(username: str, role: str):
    role = role.lower()
    if role not in VALID_ROLES:
        print(f"Invalid role '{role}'. Use one of: {', '.join(VALID_ROLES)}")
        return
    db.init_db()
    conn = db.get_connection()
    cur = conn.execute(
        "UPDATE auth_users SET role = ? WHERE username = ?",
        (role, username.strip().lower()),
    )
    conn.commit()
    print(f"Role updated for '{username}' -> {role}." if cur.rowcount else f"No such user '{username}'.")
    conn.close()


def delete_user(username: str):
    db.init_db()
    conn = db.get_connection()
    cur = conn.execute("DELETE FROM auth_users WHERE username = ?", (username.strip().lower(),))
    conn.commit()
    print(f"Deleted '{username}'." if cur.rowcount else f"No such user '{username}'.")
    conn.close()


def list_users():
    db.init_db()
    conn = db.get_connection()
    rows = conn.execute("SELECT username, role, created_at FROM auth_users ORDER BY username").fetchall()
    conn.close()
    if not rows:
        print("No dashboard login accounts yet.")
        return
    for r in rows:
        print(f"{r['username']:<20} {r['role']:<8} created {r['created_at']}")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    cmd = args[0]
    if cmd == "add" and len(args) in (3, 4):
        role = args[3] if len(args) == 4 else "viewer"
        add_user(args[1], args[2], role)
    elif cmd == "reset-password" and len(args) == 3:
        reset_password(args[1], args[2])
    elif cmd == "set-role" and len(args) == 3:
        set_role(args[1], args[2])
    elif cmd == "delete" and len(args) == 2:
        delete_user(args[1])
    elif cmd == "list":
        list_users()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
