import os
from functools import wraps
from urllib.parse import urlsplit
from datetime import datetime, timezone
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    g,
    jsonify,
)

from config import Config
from database.db import get_db, query_db, execute_db, init_db, init_app as init_db_app
from security.hasher import (
    hash_password,
    verify_password,
    simulate_dummy_verify,
    check_needs_rehash,
)
from security.csrf import init_csrf
from security.rate_limiter import (
    check_ip_rate_limit,
    is_account_locked,
    record_failed_login,
    record_successful_login,
    log_audit_event,
)
from security.tokens import (
    generate_password_reset_token,
    verify_password_reset_token,
    mark_reset_token_used,
)
from security.validators import (
    validate_username,
    validate_email,
    validate_password,
)


def is_safe_url(target: str | None) -> bool:
    """Verify that a redirect target URL is local and relative to prevent Open Redirect attacks."""
    if not target:
        return False
    ref_url = urlsplit(request.host_url)
    test_url = urlsplit(target)
    return test_url.scheme in ("", "http", "https") and (
        test_url.netloc == "" or test_url.netloc == ref_url.netloc
    )


def login_required(view_func):
    """Decorator ensuring that a route requires an authenticated user session."""
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))
        
        # Verify user still exists and is active in database
        user = query_db("SELECT * FROM users WHERE id = ?", (session["user_id"],), one=True)
        if not user or user["is_active"] != 1:
            session.clear()
            flash("Your session has expired or your account is deactivated.", "warning")
            return redirect(url_for("login"))
            
        g.user = user
        return view_func(*args, **kwargs)
    return decorated_function


def create_app(config_class=Config):
    """Application factory for the Secure Authentication System."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize database & CSRF protection
    init_db_app(app)
    init_csrf(app)

    # CLI command: flask init-db
    @app.cli.command("init-db")
    def init_db_command():
        """Initialize the database schema."""
        init_db(app)
        print("Database schema successfully initialized.")

    # Context processor to inject user into templates
    @app.context_processor
    def inject_user():
        if "user_id" in session:
            user = query_db("SELECT id, username, email FROM users WHERE id = ?", (session["user_id"],), one=True)
            return dict(current_user=user)
        return dict(current_user=None)

    # Security Headers Hook
    @app.after_request
    def apply_security_headers(response):
        """Apply defensive HTTP security headers according to OWASP recommendations."""
        # Content Security Policy (allows self and Google Fonts)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # Prevent browser caching of sensitive authenticated content
        if request.endpoint in ("dashboard", "change_password", "login", "register"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"

        return response

    # -------------------------------------------------------------
    # Routes
    # -------------------------------------------------------------

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            # Apply IP rate limiting on registration
            check_ip_rate_limit(endpoint="register")

            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            confirm_password = request.form.get("confirm_password") or ""

            # Validate username
            is_valid_u, user_err = validate_username(username)
            if not is_valid_u:
                flash(user_err, "error")
                return render_template("register.html", username=username, email=email), 400

            # Validate email
            is_valid_e, email_err = validate_email(email)
            if not is_valid_e:
                flash(email_err, "error")
                return render_template("register.html", username=username, email=email), 400

            # Validate password strength
            is_valid_p, pass_errs = validate_password(password)
            if not is_valid_p:
                for err in pass_errs:
                    flash(err, "error")
                return render_template("register.html", username=username, email=email), 400

            # Verify password confirmation matches
            if password != confirm_password:
                flash("Password and confirmation password do not match.", "error")
                return render_template("register.html", username=username, email=email), 400

            # Check for existing username or email (case-insensitive)
            existing_user = query_db(
                "SELECT id, username, email FROM users WHERE username = ? OR email = ?",
                (username, email),
                one=True,
            )
            if existing_user:
                if existing_user["username"].lower() == username.lower():
                    flash("This username is already taken. Please choose another.", "error")
                else:
                    flash("An account with this email address already exists.", "error")
                return render_template("register.html", username=username, email=email), 400

            # Hash password with Argon2id
            pw_hash = hash_password(password)

            # Insert into database
            user_id = execute_db(
                """
                INSERT INTO users (username, email, password_hash, created_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (username, email, pw_hash),
            )

            log_audit_event(
                user_id=user_id,
                event_type="REGISTER_SUCCESS",
                details=f"New user registered: {username}",
            )

            flash("Your account has been successfully created. You can now sign in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        next_url = request.args.get("next") or request.form.get("next")

        if request.method == "POST":
            # Apply IP rate limiting on login endpoint
            check_ip_rate_limit(endpoint="login")

            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""

            if not email or not password:
                flash("Please provide both email and password.", "error")
                return render_template("login.html", email=email, next=next_url), 400

            # Lookup user by email using parameterized query
            user = query_db("SELECT * FROM users WHERE email = ?", (email,), one=True)

            if not user:
                # Mitigate timing attacks by simulating verification delay
                simulate_dummy_verify(password)
                log_audit_event(
                    user_id=None,
                    event_type="LOGIN_FAILED_UNKNOWN_USER",
                    details=f"Failed login attempt for non-existent email: {email}",
                )
                flash("Invalid email or password.", "error")
                return render_template("login.html", email=email, next=next_url), 401

            # Check if account is currently locked out
            is_locked, remaining_minutes = is_account_locked(user)
            if is_locked:
                log_audit_event(
                    user_id=user["id"],
                    event_type="LOGIN_REJECTED_LOCKED_ACCOUNT",
                    details=f"Login attempted while account is locked ({remaining_minutes}m left)",
                )
                flash(
                    f"Account temporarily locked due to multiple failed login attempts. Please try again in {remaining_minutes} minute(s).",
                    "error",
                )
                return render_template("login.html", email=email, next=next_url), 429

            # Check if account is active
            if user["is_active"] != 1:
                flash("This account is currently deactivated. Please contact support.", "error")
                return render_template("login.html", email=email, next=next_url), 403

            # Verify password with Argon2id
            if not verify_password(user["password_hash"], password):
                now_locked, lock_mins = record_failed_login(user)
                log_audit_event(
                    user_id=user["id"],
                    event_type="LOGIN_FAILED_BAD_PASSWORD",
                    details="Incorrect password supplied",
                )

                if now_locked:
                    flash(
                        f"Account locked for {lock_mins} minutes due to excessive failed attempts.",
                        "error",
                    )
                    return render_template("login.html", email=email, next=next_url), 429
                else:
                    flash("Invalid email or password.", "error")
                    return render_template("login.html", email=email, next=next_url), 401

            # Verification succeeded! Check if hash requires update due to updated parameters
            if check_needs_rehash(user["password_hash"]):
                new_hash = hash_password(password)
                execute_db("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))

            # Record successful login metadata
            record_successful_login(user["id"], request.remote_addr)
            log_audit_event(
                user_id=user["id"],
                event_type="LOGIN_SUCCESS",
                details="User successfully authenticated",
            )

            # Prevent Session Fixation: Clear previous session and regenerate
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True

            flash(f"Welcome back, {user['username']}!", "success")

            # Validate redirect URL against Open Redirect vulnerabilities
            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        return render_template("login.html", next=next_url)

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        if "user_id" in session:
            user_id = session["user_id"]
            log_audit_event(user_id=user_id, event_type="LOGOUT", details="User signed out")
            session.clear()

        flash("You have been signed out securely.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = g.user

        # Fetch recent security audit records for this user
        audit_events = query_db(
            """
            SELECT event_type, ip_address, created_at, details
            FROM audit_logs
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (user["id"],),
        )

        return render_template("dashboard.html", user=user, audit_events=audit_events)

    @app.route("/dashboard/change-password", methods=["POST"])
    @login_required
    def change_password():
        user = g.user
        current_pw = request.form.get("current_password") or ""
        new_pw = request.form.get("new_password") or ""
        confirm_new_pw = request.form.get("confirm_new_password") or ""

        # Verify current password
        if not verify_password(user["password_hash"], current_pw):
            flash("Current password entered is incorrect.", "error")
            return redirect(url_for("dashboard"))

        # Validate new password
        is_valid, errors = validate_password(new_pw)
        if not is_valid:
            for err in errors:
                flash(err, "error")
            return redirect(url_for("dashboard"))

        if new_pw != confirm_new_pw:
            flash("New password confirmation does not match.", "error")
            return redirect(url_for("dashboard"))

        if current_pw == new_pw:
            flash("New password must be different from current password.", "error")
            return redirect(url_for("dashboard"))

        # Hash and update
        new_hash = hash_password(new_pw)
        execute_db("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))

        # Invalidate any open reset tokens
        execute_db("UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL", (user["id"],))

        log_audit_event(
            user_id=user["id"],
            event_type="PASSWORD_CHANGED",
            details="Password changed via user settings",
        )

        flash("Your password has been changed successfully.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        dev_reset_link = None

        if request.method == "POST":
            check_ip_rate_limit(endpoint="forgot_password")
            email = (request.form.get("email") or "").strip().lower()

            if not email:
                flash("Please enter your email address.", "error")
                return render_template("forgot_password.html"), 400

            # Generic response message to prevent email enumeration
            generic_notice = (
                "If an account with that email address exists, a password reset link has been generated."
            )

            user = query_db("SELECT id, email, is_active FROM users WHERE email = ?", (email,), one=True)

            if user and user["is_active"] == 1:
                raw_token, expires_at = generate_password_reset_token(user["id"])
                reset_url = url_for("reset_password", token=raw_token, _external=True)

                log_audit_event(
                    user_id=user["id"],
                    event_type="PASSWORD_RESET_REQUESTED",
                    details=f"Password reset requested for {email}",
                )

                # Development Mailbox Simulator: Log to server stdout and optionally provide in view
                app.logger.info(f"[DEV MAILBOX SIMULATOR] Reset link for {email}: {reset_url}")
                if app.config.get("DEV_EMAIL_SIMULATOR"):
                    dev_reset_link = reset_url
            else:
                simulate_dummy_verify("dummy_password_for_timing")
                log_audit_event(
                    user_id=None,
                    event_type="PASSWORD_RESET_NONEXISTENT",
                    details=f"Password reset requested for non-existent email: {email}",
                )

            flash(generic_notice, "info")
            return render_template("forgot_password.html", dev_reset_link=dev_reset_link)

        return render_template("forgot_password.html")

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        token = request.args.get("token") or request.form.get("token") or ""

        # Validate token
        record = verify_password_reset_token(token)
        if not record:
            flash("This password reset link is invalid or has expired. Please request a new one.", "error")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            password = request.form.get("password") or ""
            confirm_password = request.form.get("confirm_password") or ""

            is_valid, errors = validate_password(password)
            if not is_valid:
                for err in errors:
                    flash(err, "error")
                return render_template("reset_password.html", token=token), 400

            if password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template("reset_password.html", token=token), 400

            # Hash new password
            new_hash = hash_password(password)

            # Update password and reset failed attempts / lockout
            execute_db(
                """
                UPDATE users 
                SET password_hash = ?, failed_login_attempts = 0, lockout_until = NULL
                WHERE id = ?
                """,
                (new_hash, record["id"]),
            )

            # Mark token as redeemed
            mark_reset_token_used(record["reset_id"])

            log_audit_event(
                user_id=record["id"],
                event_type="PASSWORD_RESET_SUCCESS",
                details="Password successfully reset via secure token",
            )

            flash("Your password has been reset successfully! You can now sign in with your new password.", "success")
            return redirect(url_for("login"))

        return render_template("reset_password.html", token=token)

    # -------------------------------------------------------------
    # Error Handlers
    # -------------------------------------------------------------

    @app.errorhandler(400)
    def bad_request_error(e):
        return render_template("errors/400.html", description=getattr(e, "description", "Bad Request")), 400

    @app.errorhandler(404)
    def not_found_error(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def rate_limit_error(e):
        return render_template("errors/429.html", description=getattr(e, "description", "Too Many Requests")), 429

    @app.errorhandler(500)
    def internal_server_error(e):
        # Do not expose stack traces or raw errors
        return render_template("errors/500.html"), 500

    return app


# Application instance for running with `flask run` or `python app.py`
app = create_app()

if __name__ == "__main__":
    # Ensure database is initialized before starting
    init_db(app)
    # Never bind to 0.0.0.0 with debug=True in production!
    port = int(os.getenv("PORT", 5000))
    print(f"\n=======================================================")
    print(f" Secure Authentication System Running on http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    app.run(host="127.0.0.1", port=port, debug=True)
