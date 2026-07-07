"""
app.py
Dark Web Exposure Awareness Simulator
--------------------------------------
An educational Flask application that demonstrates, in a fully synthetic
sandbox, how leaked credentials surface in breach datasets and what risks
that exposure creates (mapped to MITRE ATT&CK techniques and illustrative
Verizon DBIR-style statistics).

Group 8 | Dark Web Exposure Awareness Simulator
"""

import os
import io
import base64
import secrets
from collections import Counter

import pyotp
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

from database import init_db, get_connection, _hash as hash_value
from threat_intel import MITRE_TECHNIQUES, DBIR_STATS, DBIR_YEARLY_TREND, get_techniques_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

APP_NAME = "DarkScope"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_current_user():
    if not session.get("user_id"):
        return None
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return user


def make_qr_data_uri(otp_uri: str) -> str:
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def check_breach(email: str):
    """Look up an email in the simulated breach dataset and return
    matched rows plus an aggregated, deduplicated MITRE technique list."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM breach_dataset WHERE email = ? COLLATE NOCASE",
        (email,),
    ).fetchall()
    conn.close()

    matches = [dict(r) for r in rows]
    technique_codes = set()
    for m in matches:
        for code in m["mitre_techniques"].split(","):
            technique_codes.add(code.strip())

    techniques = [
        {"code": c, **MITRE_TECHNIQUES.get(c, {"name": c, "tactic": "N/A", "summary": ""})}
        for c in sorted(technique_codes)
    ]
    return matches, techniques


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html", app_name=APP_NAME)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html", app_name=APP_NAME)

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", app_name=APP_NAME)

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html", app_name=APP_NAME)

        conn = get_connection()
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()
        if existing:
            conn.close()
            flash("Username or email already registered.", "danger")
            return render_template("register.html", app_name=APP_NAME)

        pw_hash = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, pw_hash),
        )
        conn.commit()
        user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
        conn.close()

        session["pending_user_id"] = user_id
        flash("Account created. Let's set up two-factor authentication.", "success")
        return redirect(url_for("mfa_setup"))

    return render_template("register.html", app_name=APP_NAME)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form["identifier"].strip().lower()
        password = request.form["password"]

        conn = get_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier),
        ).fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username/email or password.", "danger")
            return render_template("login.html", app_name=APP_NAME)

        if user["mfa_enabled"]:
            session["pending_user_id"] = user["id"]
            return redirect(url_for("mfa_verify"))
        else:
            session["pending_user_id"] = user["id"]
            flash("Two-factor authentication is required. Please finish setup.", "warning")
            return redirect(url_for("mfa_setup"))

    return render_template("login.html", app_name=APP_NAME)


@app.route("/mfa-setup", methods=["GET", "POST"])
def mfa_setup():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if user["mfa_enabled"]:
        conn.close()
        return redirect(url_for("mfa_verify"))

    if not user["mfa_secret"]:
        secret = pyotp.random_base32()
        conn.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (secret, user_id))
        conn.commit()
    else:
        secret = user["mfa_secret"]

    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(name=user["email"], issuer_name=APP_NAME)
    qr_data_uri = make_qr_data_uri(otp_uri)

    if request.method == "POST":
        code = request.form.get("otp_code", "").strip()
        if totp.verify(code, valid_window=1):
            conn.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            session.pop("pending_user_id", None)
            session["user_id"] = user_id
            flash("Two-factor authentication enabled. Welcome aboard!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect code. Check your authenticator app and try again.", "danger")

    conn.close()
    return render_template(
        "mfa_setup.html",
        app_name=APP_NAME,
        secret=secret,
        qr_data_uri=qr_data_uri,
    )


@app.route("/mfa-verify", methods=["GET", "POST"])
def mfa_verify():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if request.method == "POST":
        code = request.form.get("otp_code", "").strip()
        totp = pyotp.TOTP(user["mfa_secret"])
        if totp.verify(code, valid_window=1):
            session.pop("pending_user_id", None)
            session["user_id"] = user_id
            flash("Login verified.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect authentication code.", "danger")

    return render_template("mfa_verify.html", app_name=APP_NAME)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Core app routes
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    conn = get_connection()
    history = conn.execute(
        "SELECT * FROM scan_history WHERE user_id = ? ORDER BY scanned_at DESC LIMIT 10",
        (user["id"],),
    ).fetchall()

    technique_counter = Counter()
    for h in history:
        if h["matched_sources"]:
            conn2 = get_connection()
            rows = conn2.execute(
                "SELECT mitre_techniques FROM breach_dataset WHERE email = ? COLLATE NOCASE",
                (h["scanned_email"],),
            ).fetchall()
            conn2.close()
            for r in rows:
                for c in r["mitre_techniques"].split(","):
                    technique_counter[c.strip()] += 1
    conn.close()

    top_techniques = [
        {"code": c, "count": n, **MITRE_TECHNIQUES.get(c, {"name": c, "tactic": "N/A"})}
        for c, n in technique_counter.most_common(5)
    ]

    return render_template(
        "dashboard.html",
        app_name=APP_NAME,
        user=user,
        history=history,
        dbir_stats=DBIR_STATS,
        dbir_trend=DBIR_YEARLY_TREND,
        top_techniques=top_techniques,
    )


@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    user = get_current_user()
    result = None
    matches = []
    techniques = []

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        matches, techniques = check_breach(email)
        result = "breached" if matches else "clean"

        conn = get_connection()
        sources = ",".join(sorted({m["source_name"] for m in matches})) if matches else ""
        conn.execute(
            "INSERT INTO scan_history (user_id, scanned_email, result, matched_sources) VALUES (?, ?, ?, ?)",
            (user["id"], email, result, sources),
        )
        conn.commit()
        conn.close()

        if result == "breached":
            return render_template(
                "warning.html",
                app_name=APP_NAME,
                email=email,
                matches=matches,
                techniques=techniques,
            )
        else:
            flash(f"No exposure found for {email} in the simulated breach dataset.", "success")

    return render_template("scan.html", app_name=APP_NAME, result=result)


@app.route("/learn")
@login_required
def learn():
    return render_template(
        "learn.html",
        app_name=APP_NAME,
        techniques=MITRE_TECHNIQUES,
        dbir_stats=DBIR_STATS,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
