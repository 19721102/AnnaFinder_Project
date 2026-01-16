from __future__ import annotations

from typing import Any, Callable, Dict, Set

from fastapi import HTTPException, Request

from security_events import emit_event, sanitize_str

ROLE_OWNER = "OWNER"
ROLE_MEMBER = "MEMBER"
ROLE_VIEWER = "VIEWER"

PERM_INVITE_CREATE = "HOUSEHOLD_INVITE_CREATE"
PERM_INVITE_ACCEPT = "HOUSEHOLD_INVITE_ACCEPT"
PERM_INVITE_REVOKE = "HOUSEHOLD_INVITE_REVOKE"
PERM_MEMBER_VIEW = "HOUSEHOLD_MEMBER_VIEW"
PERM_MEMBER_ROLE_CHANGE = "HOUSEHOLD_MEMBER_ROLE_CHANGE"
PERM_MEMBER_REMOVE = "HOUSEHOLD_MEMBER_REMOVE"
PERM_HOUSEHOLD_PROFILE_UPDATE = "HOUSEHOLD_PROFILE_UPDATE"
PERM_ITEM_CREATE = "ITEM_CREATE"
PERM_ITEM_UPDATE = "ITEM_UPDATE"
PERM_ITEM_DELETE = "ITEM_DELETE"
PERM_DATA_EXPORT = "DATA_EXPORT"
PERM_DATA_DELETE = "DATA_DELETE"
PERM_FEEDBACK_SUBMIT = "FEEDBACK_SUBMIT"

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    ROLE_OWNER: {
        PERM_INVITE_CREATE,
        PERM_INVITE_ACCEPT,
        PERM_INVITE_REVOKE,
        PERM_MEMBER_VIEW,
        PERM_MEMBER_ROLE_CHANGE,
        PERM_MEMBER_REMOVE,
        PERM_HOUSEHOLD_PROFILE_UPDATE,
        PERM_ITEM_CREATE,
        PERM_ITEM_UPDATE,
        PERM_ITEM_DELETE,
        PERM_DATA_EXPORT,
        PERM_DATA_DELETE,
        PERM_FEEDBACK_SUBMIT,
    },
    ROLE_MEMBER: {
        PERM_INVITE_ACCEPT,
        PERM_MEMBER_VIEW,
        PERM_ITEM_CREATE,
        PERM_ITEM_UPDATE,
        PERM_ITEM_DELETE,
        PERM_DATA_EXPORT,
        PERM_FEEDBACK_SUBMIT,
    },
    ROLE_VIEWER: {PERM_INVITE_ACCEPT, PERM_MEMBER_VIEW, PERM_FEEDBACK_SUBMIT},
}


def has_permission(role: str, permission: str) -> bool:
    allowed = ROLE_PERMISSIONS.get(role, set())
    return permission in allowed


def require_permission(
    session: Dict[str, Any],
    permission: str,
    request: Request,
    get_role_fn: Callable[[str, str], str],
    build_ctx_fn: Callable[[Request, Dict[str, Any]], Dict[str, Any]],
) -> str:
    role = get_role_fn(session["user_id"], session["household_id"])
    if has_permission(role, permission):
        return role

    ctx = build_ctx_fn(request, session)
    emit_event(
        {
            **ctx,
            "event": "AUTHZ_DENY",
            "severity": "MEDIUM",
            "outcome": "FAIL",
            "target": {"resource": sanitize_str(request.url.path)},
            "meta": {"permission": sanitize_str(permission)},
        }
    )
    raise HTTPException(status_code=403, detail="Forbidden")
