from flask import Blueprint, render_template, request, redirect, flash, session
from bson import ObjectId
from app.utils import db as db_module
from app.utils.rbac import roles_required, normalize_roles

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
@roles_required("admin")
def admin():
    users = []
    for user in db_module.db.users.find().sort("username", 1):
        user["roles"] = normalize_roles(user)
        users.append(user)
    return render_template("pages/admin.html", users=users)


@admin_bp.route("/admin/user/<user_id>/update", methods=["POST"])
@roles_required("admin")
def update_user(user_id):
    target = db_module.db.users.find_one({"_id": ObjectId(user_id)})
    if not target:
        flash("User not found.", "danger")
        return redirect("/admin")

    if target.get("username") == session.get("user"):
        flash("You cannot modify your own admin account from this panel.", "warning")
        return redirect("/admin")

    selected_roles = request.form.getlist("roles")
    roles = normalize_roles(selected_roles)
    status = request.form.get("status", target.get("status", "active"))
    if status not in ["active", "blocked"]:
        status = "active"

    db_module.db.users.update_one(
        {"_id": target["_id"]},
        {
            "$set": {
                "roles": roles,
                "role": roles[-1],
                "status": status,
            }
        },
    )

    flash(f"Updated {target['username']} successfully.", "success")
    return redirect("/admin")
