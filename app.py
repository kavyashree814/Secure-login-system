from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import re
import os
from functools import wraps

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-this"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

DATABASE = "users.db"


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.commit()
    db.close()


def valid_username(username):
    return re.fullmatch(
        r"[A-Za-z0-9_]{3,30}",
        username
    ) is not None


def valid_email(email):
    return re.fullmatch(
        r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
        email
    ) is not None


def valid_password(password):
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
    )


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not valid_username(username):
            flash(
                "Username must contain 3-30 characters and only letters, numbers and underscore.",
                "error"
            )
            return redirect(url_for("register"))

        if not valid_email(email):
            flash("Enter a valid email address.", "error")
            return redirect(url_for("register"))

        if not valid_password(password):
            flash(
                "Password must contain at least 8 characters, "
                "one uppercase letter, one lowercase letter and one number.",
                "error"
            )
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        db = get_db()

        try:
            existing_user = db.execute(
                """
                SELECT id
                FROM users
                WHERE username = ? OR email = ?
                """,
                (username, email)
            ).fetchone()

            if existing_user:
                flash("Username or email already exists.", "error")
                return redirect(url_for("register"))

            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt()
            )

            db.execute(
                """
                INSERT INTO users
                (username, email, password)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    password_hash.decode("utf-8")
                )
            )

            db.commit()

            flash(
                "Registration successful. Please login.",
                "success"
            )

            return redirect(url_for("login"))

        finally:
            db.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username_or_email = request.form.get(
            "username_or_email",
            ""
        ).strip()

        password = request.form.get("password", "")

        if not username_or_email or not password:
            flash(
                "Please enter your username/email and password.",
                "error"
            )
            return redirect(url_for("login"))

        db = get_db()

        user = db.execute(
            """
            SELECT id, username, email, password
            FROM users
            WHERE username = ? OR email = ?
            """,
            (
                username_or_email,
                username_or_email.lower()
            )
        ).fetchone()

        db.close()

        if user:

            stored_hash = user["password"].encode("utf-8")

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_hash
            ):

                session.clear()

                session["user_id"] = user["id"]
                session["username"] = user["username"]

                return redirect(url_for("dashboard"))

        flash(
            "Invalid username/email or password.",
            "error"
        )

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )