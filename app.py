from __future__ import annotations

import os
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Optional

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "users.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-production")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_: Optional[BaseException]) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def seed_user(db: sqlite3.Connection, email: str, password: str, role: str, full_name: str, package_name: str) -> None:
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return
    db.execute(
        "INSERT INTO users (email, password_hash, role, full_name, package_name) VALUES (?, ?, ?, ?, ?)",
        (email, generate_password_hash(password), role, full_name, package_name),
    )
    db.commit()


def init_db() -> None:
    db = sqlite3.connect(DATABASE)
    db.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            full_name TEXT NOT NULL,
            package_name TEXT NOT NULL DEFAULT 'Premium',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        '''
    )
    db.commit()
    seed_user(db, "admin@novastream.local", "Admin123!", "admin", "Admin Nutzer", "Ultra")
    seed_user(db, "test@novastream.local", "Test123!", "user", "Test Nutzer", "Premium")
    db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    return render_template("landing.html", logged_in=bool(session.get("user_id")), user_name=session.get("user_name"))


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    users = []
    if session.get("user_role") == "admin":
        users = db.execute(
            "SELECT id, email, full_name, role, package_name, is_active, created_at FROM users ORDER BY id ASC"
        ).fetchall()
    return render_template("dashboard.html", user=user, users=users, is_admin=session.get("user_role") == "admin")


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    package_name = (data.get("package_name") or "Premium").strip()

    if not full_name or not email or not password:
        return jsonify({"ok": False, "message": "Bitte alle Pflichtfelder ausfüllen."}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "message": "Passwort muss mindestens 8 Zeichen lang sein."}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return jsonify({"ok": False, "message": "Diese E-Mail existiert bereits."}), 409

    db.execute(
        "INSERT INTO users (email, password_hash, role, full_name, package_name) VALUES (?, ?, 'user', ?, ?)",
        (email, generate_password_hash(password), full_name, package_name),
    )
    db.commit()
    return jsonify({"ok": True, "message": "Registrierung erfolgreich. Du kannst dich jetzt anmelden."})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user is None:
        return jsonify({"ok": False, "message": "Benutzer nicht gefunden."}), 404
    if not user["is_active"]:
        return jsonify({"ok": False, "message": "Benutzer ist deaktiviert."}), 403
    if not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "message": "Falsches Passwort."}), 401

    session.clear()
    session["user_id"] = user["id"]
    session["user_role"] = user["role"]
    session["user_email"] = user["email"]
    session["user_name"] = user["full_name"]
    return jsonify({"ok": True, "redirect": url_for("dashboard")})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True, "redirect": url_for("home")})


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
