from flask import Blueprint, render_template, request, redirect, session, flash
from app.utils import db as db_module
from app.utils.rbac import normalize_roles
import pyotp, qrcode, io, base64

auth_bp = Blueprint("auth", __name__)


def get_default_roles(username):
    username = (username or "").strip().lower()

    if db_module.db.users.count_documents({"roles": "admin"}) == 0 and db_module.db.users.count_documents({"role": "admin"}) == 0:
        return ["user", "developer", "admin"]

    if username == "manish":
        return ["user", "developer", "admin"]

    return ["user"]


@auth_bp.route("/")
def home():
    return redirect("/login")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]

        user = db_module.db.users.find_one({"username": u})

        if user and user.get("password") == p:
            if user.get("status", "active") != "active":
                flash("Your account is blocked. Please contact an admin.", "danger")
                return render_template("pages/login.html")

            session["temp_user"] = u
            return redirect("/otp")

        flash("Invalid credentials", "danger")

    return render_template("pages/login.html")


@auth_bp.route("/otp", methods=["GET", "POST"])
def otp():
    temp_user = session.get("temp_user")
    if not temp_user:
        flash("Please log in again.", "warning")
        return redirect("/login")

    if request.method == "POST":
        otp_value = request.form["otp"]
        user = db_module.db.users.find_one({"username": temp_user})

        if not user:
            session.clear()
            flash("User session expired. Please log in again.", "danger")
            return redirect("/login")

        if user.get("status", "active") != "active":
            session.clear()
            flash("Your account is blocked. Please contact an admin.", "danger")
            return redirect("/login")

        totp = pyotp.TOTP(user["secret"])

        if totp.verify(otp_value):
            roles = normalize_roles(user)
            session["user"] = user["username"]
            session["roles"] = roles
            session["role"] = roles[-1]
            session["secret"] = user["secret"]
            session.pop("temp_user", None)
            flash("Login successful.", "success")
            return redirect("/dashboard")

        flash("Invalid OTP", "danger")

    return render_template("pages/otp.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]

        if not u or not p:
            flash("Username and password are required.", "danger")
            return render_template("pages/register.html")

        if db_module.db.users.find_one({"username": u}):
            flash("Username already exists.", "warning")
            return render_template("pages/register.html")

        secret = pyotp.random_base32()
        roles = get_default_roles(u)

        db_module.db.users.insert_one(
            {
                "username": u,
                "password": p,
                "role": roles[-1],
                "roles": roles,
                "status": "active",
                "secret": secret,
            }
        )

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=u, issuer_name="AMQRES")

        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")

        qr = base64.b64encode(buf.getvalue()).decode()

        return render_template("pages/register_qr.html", qr=qr)

    return render_template("pages/register.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect("/login")
