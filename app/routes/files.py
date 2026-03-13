from flask import Blueprint, render_template, request, session, redirect, flash, send_file
from app.services.crypto_service import encrypt_file, decrypt_file
from app.models.file_model import add_file, get_user_files, get_file, delete_file
from app.utils.rbac import login_required, has_role
import pyotp
import os
import io

files_bp = Blueprint("files", __name__)


def can_access_file(file_doc):
    if not file_doc:
        return False
    return file_doc.get("owner") == session.get("user") or has_role("admin")


@files_bp.route("/dashboard")
@login_required
def dashboard():
    files = get_user_files(session["user"])
    return render_template("pages/dashboard.html", files=files)


@files_bp.route("/encrypt", methods=["POST"])
@login_required
def encrypt():
    f = request.files.get("file")
    if not f or not getattr(f, "filename", ""):
        flash("Please choose a file to encrypt.", "warning")
        return redirect("/dashboard")

    try:
        path = encrypt_file(f)
        add_file(session["user"], f.filename, path)
        flash("File encrypted successfully", "success")
    except Exception as exc:
        flash(str(exc), "danger")

    return redirect("/dashboard")


@files_bp.route("/decrypt/<id>", methods=["POST"])
@login_required
def decrypt(id):
    otp = request.form["otp"]
    totp = pyotp.TOTP(session["secret"])

    if not totp.verify(otp):
        flash("Invalid OTP", "danger")
        return redirect("/dashboard")

    file_doc = get_file(id)
    if not can_access_file(file_doc):
        flash("Access denied.", "danger")
        return redirect("/dashboard")

    try:
        out = decrypt_file(file_doc["path"])
    except Exception as exc:
        flash(str(exc), "danger")
        return redirect("/dashboard")

    flash("File decrypted", "success")
    return send_file(out, as_attachment=True)


@files_bp.route("/preview/<id>")
@login_required
def preview(id):
    file_doc = get_file(id)
    if not can_access_file(file_doc):
        flash("Access denied.", "danger")
        return redirect("/dashboard")

    return send_file(file_doc["path"], as_attachment=False)


@files_bp.route("/reencrypt/<id>")
@login_required
def reencrypt(id):
    file_doc = get_file(id)
    if not can_access_file(file_doc):
        flash("Access denied.", "danger")
        return redirect("/dashboard")

    try:
        # Decrypt first to recover plaintext
        plaintext_path = decrypt_file(file_doc["path"])

        with open(plaintext_path, "rb") as source_file:
            buffer = io.BytesIO(source_file.read())
            buffer.filename = file_doc["filename"]
            new_path = encrypt_file(buffer)

        # remove old encrypted artifacts
        for suffix in ["", ".ct", ".sig"]:
            try:
                os.remove(file_doc["path"] + suffix)
            except Exception:
                pass

        # optional: update DB path if your app supports it
        flash("File re-encrypted", "success")
    except Exception as exc:
        flash(str(exc), "danger")

    return redirect("/dashboard")


@files_bp.route("/delete/<id>")
@login_required
def delete(id):
    file_doc = get_file(id)
    if not can_access_file(file_doc):
        flash("Access denied.", "danger")
        return redirect("/dashboard")

    delete_file(id)
    for suffix in ["", ".ct", ".sig"]:
        try:
            os.remove(file_doc["path"] + suffix)
        except Exception:
            pass
    flash("File deleted", "warning")
    return redirect("/dashboard")