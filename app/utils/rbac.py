from functools import wraps
from flask import session, redirect, flash

VALID_ROLES = ["user", "developer", "admin"]


def normalize_roles(user_or_roles):
    """Accept a user document, role string, role list, or session value."""
    source = user_or_roles
    if isinstance(user_or_roles, dict):
        if "roles" in user_or_roles:
            source = user_or_roles.get("roles", [])
        else:
            source = user_or_roles.get("role", "user")

    if isinstance(source, str):
        roles = [source]
    elif isinstance(source, (list, tuple, set)):
        roles = list(source)
    else:
        roles = ["user"]

    normalized = {role for role in roles if role in VALID_ROLES}

    if "admin" in normalized:
        normalized.update({"developer", "user"})
    elif "developer" in normalized:
        normalized.add("user")

    if not normalized:
        normalized = {"user"}

    return sorted(normalized, key=VALID_ROLES.index)



def has_role(role, roles=None):
    current_roles = normalize_roles(roles if roles is not None else session.get("roles", []))
    return role in current_roles



def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            flash("Please log in first.", "warning")
            return redirect("/login")
        return func(*args, **kwargs)

    return wrapper



def roles_required(*required_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user" not in session:
                flash("Please log in first.", "warning")
                return redirect("/login")

            current_roles = normalize_roles(session.get("roles", []))
            if not any(role in current_roles for role in required_roles):
                flash("Access denied.", "danger")
                return redirect("/dashboard")

            return func(*args, **kwargs)

        return wrapper

    return decorator
