from flask import Blueprint, render_template
from app.utils import db as db_module
from app.utils.rbac import roles_required, normalize_roles

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/analytics")
@roles_required("developer")
def analytics():
    users_cursor = list(db_module.db.users.find())
    files_cursor = list(db_module.db.files.find())

    total_users = len(users_cursor)
    total_files = len(files_cursor)
    active_users = sum(1 for u in users_cursor if u.get("status", "active") == "active")
    blocked_users = total_users - active_users

    role_counts = {"user": 0, "developer": 0, "admin": 0}
    for user in users_cursor:
        for role in normalize_roles(user):
            role_counts[role] += 1

    owner_counts = {}
    for file_doc in files_cursor:
        owner = file_doc.get("owner", "unknown")
        owner_counts[owner] = owner_counts.get(owner, 0) + 1

    top_owners = sorted(owner_counts.items(), key=lambda item: (-item[1], item[0]))[:5]

    encryption_ratio = round((total_files / total_users), 2) if total_users else 0
    active_ratio = round((active_users / total_users) * 100, 1) if total_users else 0

    return render_template(
        "pages/analytics.html",
        users=total_users,
        files=total_files,
        active_users=active_users,
        blocked_users=blocked_users,
        role_counts=role_counts,
        top_owners=top_owners,
        encryption_ratio=encryption_ratio,
        active_ratio=active_ratio,
    )
