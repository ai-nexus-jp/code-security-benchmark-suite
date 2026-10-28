from functools import wraps
from typing import Optional, Dict, Any, Callable
from flask import g, abort

from bench_app.database.connection import SessionLocal, User


def get_user_profile_unauthorized_idor(requested_user_id: int) -> Optional[Dict[str, Any]]:
    """
    VULN-013: Insecure Direct Object Reference (IDOR).
    Fetches any user profile directly by ID without verifying if the requesting user owns or has access to the resource.
    """
    session = SessionLocal()
    try:
        # // CASE: VULN-013
        user = session.query(User).filter(User.id == requested_user_id).first()
        if user:
            return {"id": user.id, "username": user.username, "email": user.email}
        return None
    finally:
        session.close()


def require_ownership(f: Callable):
    """
    Decorator for verifying that the current session user matches the requested target user ID.
    SAFE-011: Authorization check is properly enforced in the outer decoration layer.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        target_id = kwargs.get("user_id")
        current_user_id = getattr(g, "current_user_id", None)
        if current_user_id is None or current_user_id != target_id:
            # Reject unauthorized access
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@require_ownership
def get_user_profile_protected_by_decorator(user_id: int) -> Optional[Dict[str, Any]]:
    """
    SAFE-011: Safe retrieval protected by @require_ownership decorator.
    Static scanners often flag direct ID lookup inside the function body ignoring the decorator guard.
    """
    session = SessionLocal()
    try:
        # // CASE: SAFE-011
        user = session.query(User).filter(User.id == user_id).first()
        if user:
            return {"id": user.id, "username": user.username, "email": user.email}
        return None
    finally:
        session.close()
