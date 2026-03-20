from __future__ import annotations

import hmac
import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Optional

import stripe
from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "users.db"

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "change-this-in-production"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
)

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000").rstrip("/")

PRICE_IDS = {
    "Basic": os.environ.get("STRIPE_PRICE_BASIC", ""),
    "Premium": os.environ.get("STRIPE_PRICE_PREMIUM", ""),
    "Ultra": os.environ.get("STRIPE_PRICE_ULTRA", ""),
}

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


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
    db.execute("""
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
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            stripe_session_id TEXT UNIQUE,
            package_name TEXT NOT NULL,
            amount_cents INTEGER,
            currency TEXT DEFAULT 'eur',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
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


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def get_or_set_csrf() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> None:
    sent = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    if not expected or not sent or not hmac.compare_digest(sent, expected):
        abort(400, description="Ungültiger CSRF-Token.")


@app.before_request
def ensure_csrf_token():
    if request.method == "GET":
        get_or_set_csrf()


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self' https://js.stripe.com; "
        "frame-src https://checkout.stripe.com; "
        "connect-src 'self' https://api.stripe.com;"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def current_user():
    if session.get("user_id") is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


@app.route("/")
def home():
    return render_template(
        "landing.html",
        logged_in=bool(session.get("user_id")),
        user_name=session.get("user_name"),
        csrf_token=get_or_set_csrf(),
        stripe_enabled=bool(STRIPE_SECRET_KEY and all(PRICE_IDS.values())),
    )


@app.route("/login")
def login_page():
    return render_template("login.html", csrf_token=get_or_set_csrf())


@app.route("/register")
def register_page():
    return render_template("register.html", csrf_token=get_or_set_csrf())


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = current_user()
    payments = db.execute(
        """
        SELECT id, package_name, amount_cents, currency, status, created_at
        FROM payments WHERE user_id = ? ORDER BY id DESC LIMIT 10
        """,
        (user["id"],),
    ).fetchall()

    users = []
    if session.get("user_role") == "admin":
        users = db.execute(
            """
            SELECT id, email, full_name, role, package_name, is_active, created_at
            FROM users ORDER BY id ASC
            """
        ).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        users=users,
        payments=payments,
        is_admin=session.get("user_role") == "admin",
        csrf_token=get_or_set_csrf(),
        stripe_enabled=bool(STRIPE_SECRET_KEY and all(PRICE_IDS.values())),
    )


@app.route("/checkout")
@login_required
def checkout_page():
    return render_template(
        "checkout.html",
        csrf_token=get_or_set_csrf(),
        stripe_enabled=bool(STRIPE_SECRET_KEY and all(PRICE_IDS.values())),
        current_package=current_user()["package_name"],
    )


@app.route("/payment/success")
@login_required
def payment_success():
    session_id = request.args.get("session_id", "")
    payment = None
    if session_id:
        payment = get_db().execute("SELECT * FROM payments WHERE stripe_session_id = ?", (session_id,)).fetchone()
    return render_template("payment_success.html", payment=payment, csrf_token=get_or_set_csrf())


@app.route("/payment/cancel")
@login_required
def payment_cancel():
    return render_template("payment_cancel.html", csrf_token=get_or_set_csrf())


@app.route("/api/register", methods=["POST"])
def register():
    validate_csrf()
    data = request.get_json(silent=True) or {}
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    package_name = (data.get("package_name") or "Premium").strip()

    if not full_name or not email or not password:
        return jsonify({"ok": False, "message": "Bitte alle Pflichtfelder ausfüllen."}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "message": "Passwort muss mindestens 8 Zeichen lang sein."}), 400
    if package_name not in PRICE_IDS:
        return jsonify({"ok": False, "message": "Ungültiges Paket."}), 400

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
    validate_csrf()
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"ok": False, "message": "E-Mail und Passwort sind erforderlich."}), 400

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
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"ok": True, "redirect": url_for("dashboard")})


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    validate_csrf()
    session.clear()
    return jsonify({"ok": True, "redirect": url_for("home")})


@app.route("/api/admin/users", methods=["POST"])
@login_required
@admin_required
def create_user_admin():
    validate_csrf()
    data = request.get_json(silent=True) or {}
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    role = (data.get("role") or "user").strip()
    package_name = (data.get("package_name") or "Premium").strip()

    if not full_name or not email or not password:
        return jsonify({"ok": False, "message": "Bitte alle Pflichtfelder ausfüllen."}), 400
    if role not in {"admin", "user"}:
        return jsonify({"ok": False, "message": "Ungültige Rolle."}), 400
    if package_name not in PRICE_IDS:
        return jsonify({"ok": False, "message": "Ungültiges Paket."}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return jsonify({"ok": False, "message": "E-Mail existiert bereits."}), 409

    db.execute(
        "INSERT INTO users (email, password_hash, role, full_name, package_name) VALUES (?, ?, ?, ?, ?)",
        (email, generate_password_hash(password), role, full_name, package_name),
    )
    db.commit()
    return jsonify({"ok": True, "message": "Nutzer angelegt."})


@app.route("/api/admin/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id: int):
    validate_csrf()
    db = get_db()
    row = db.execute("SELECT id, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "message": "Nutzer nicht gefunden."}), 404
    new_value = 0 if row["is_active"] else 1
    db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_value, user_id))
    db.commit()
    return jsonify({"ok": True, "message": "Nutzerstatus geändert."})


@app.route("/api/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    validate_csrf()
    if not STRIPE_SECRET_KEY or not all(PRICE_IDS.values()):
        return jsonify({"ok": False, "message": "Stripe ist noch nicht konfiguriert."}), 400

    data = request.get_json(silent=True) or {}
    package_name = (data.get("package_name") or "").strip()
    if package_name not in PRICE_IDS or not PRICE_IDS[package_name]:
        return jsonify({"ok": False, "message": "Ungültiges Paket."}), 400

    user = current_user()
    try:
        checkout_session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[{"price": PRICE_IDS[package_name], "quantity": 1}],
            customer_email=user["email"],
            metadata={"user_id": user["id"], "package_name": package_name},
            success_url=f"{BASE_URL}{url_for('payment_success')}?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}{url_for('payment_cancel')}",
        )
    except Exception as exc:
        return jsonify({"ok": False, "message": f"Stripe-Fehler: {exc}"}), 400

    get_db().execute(
        "INSERT OR IGNORE INTO payments (user_id, stripe_session_id, package_name, status) VALUES (?, ?, ?, 'pending')",
        (user["id"], checkout_session.id, package_name),
    )
    get_db().commit()
    return jsonify({"ok": True, "url": checkout_session.url})


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")
    if not STRIPE_WEBHOOK_SECRET:
        return jsonify({"ok": False, "message": "Webhook secret fehlt."}), 400
    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig_header, secret=STRIPE_WEBHOOK_SECRET)
    except Exception:
        return jsonify({"ok": False, "message": "Ungültiger Webhook."}), 400

    if event["type"] == "checkout.session.completed":
        obj = event["data"]["object"]
        session_id = obj["id"]
        metadata = obj.get("metadata") or {}
        user_id = int(metadata.get("user_id", 0))
        package_name = metadata.get("package_name", "Premium")
        amount_total = obj.get("amount_total") or 0
        currency = obj.get("currency") or "eur"

        db = sqlite3.connect(DATABASE)
        db.execute("UPDATE payments SET status = 'paid', amount_cents = ?, currency = ? WHERE stripe_session_id = ?",
                   (amount_total, currency, session_id))
        if user_id:
            db.execute("UPDATE users SET package_name = ? WHERE id = ?", (package_name, user_id))
        db.commit()
        db.close()

    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
