"""
Basic example demonstrating fastapi-rbac-authz usage.

Run with:
    uvicorn examples.basic_app:app --reload

Then visit:
    - http://localhost:18000/docs - OpenAPI documentation
    - http://localhost:18000/_rbac - Authorization visualization UI
"""

from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException

from fastapi_rbac import (
    Contextual,
    ContextualAuthz,
    Global,
    RBACAuthz,
    RBACRouter,
    RBACUser,
)


# =============================================================================
# User Model
# =============================================================================
class User:
    def __init__(self, user_id: str, roles: set[str]):
        self.user_id = user_id
        self.roles = roles


# Fake user database
USERS = {
    "admin-token": User(user_id="admin-1", roles={"admin"}),
    "user-token": User(user_id="user-1", roles={"user"}),
    "viewer-token": User(user_id="viewer-1", roles={"viewer"}),
}

# Fake report database (report_id -> owner_id)
REPORTS = {
    1: {"title": "Q1 Sales Report", "owner_id": "user-1"},
    2: {"title": "Q2 Sales Report", "owner_id": "user-1"},
    3: {"title": "Engineering Report", "owner_id": "admin-1"},
}


# =============================================================================
# Role Permissions
# =============================================================================
PERMISSIONS = {
    "admin": {
        Global("*"),  # Admin can do everything
    },
    "user": {
        Contextual("report:read"),  # Can read reports they own
        Contextual("report:update"),  # Can update reports they own
        Global("report:create"),  # Can create new reports (no context needed)
    },
    "viewer": {
        Contextual("report:read"),  # Can only read reports they have access to
    },
}


# =============================================================================
# Authentication Dependency
# =============================================================================
async def get_current_user(x_token: Annotated[str, Header()]) -> User:
    """Simulate authentication via X-Token header."""
    user = USERS.get(x_token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


# =============================================================================
# Context Check
# =============================================================================
class ReportOwnerContext(ContextualAuthz[User]):
    """Check if user owns the report or is allowed to access it."""

    def __init__(
        self,
        report_id: int,
        user: Annotated[User, Depends(RBACUser)],
    ):
        self.user = user
        self.report_id = report_id

    async def has_permissions(self) -> bool:
        report = REPORTS.get(self.report_id)
        if not report:
            return False
        # User can access if they own the report
        return report["owner_id"] == self.user.user_id


# =============================================================================
# Application Setup
# =============================================================================
app = FastAPI(
    title="RBAC Example",
    description="Example app demonstrating fastapi-rbac-authz",
)

RBACAuthz(
    app,
    get_roles=lambda user: user.roles,
    permissions=PERMISSIONS,
    user_dependency=get_current_user,
    ui_path="/_rbac",
)


# =============================================================================
# Routes
# =============================================================================
router = RBACRouter(
    prefix="/reports",
    tags=["Reports"],
    permissions={"report:read"},
    contexts=[ReportOwnerContext],
)


@router.get("/{report_id}")
async def get_report(report_id: int):
    """Get a specific report. Requires report:read permission + ownership check."""
    report = REPORTS.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"id": report_id, **report}


@router.put("/{report_id}", permissions={"report:update"})
async def update_report(report_id: int, title: str):
    """Update a report. Requires report:update permission + ownership check."""
    report = REPORTS.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    report["title"] = title
    return {"id": report_id, **report}


@router.post("", permissions={"report:create"}, contexts=[])
async def create_report(title: str, user: Annotated[User, Depends(RBACUser)]):
    """Create a new report. Requires report:create permission (no context check)."""
    new_id = max(REPORTS.keys()) + 1
    REPORTS[new_id] = {"title": title, "owner_id": user.user_id}
    return {"id": new_id, **REPORTS[new_id]}


# List endpoint without context (shows all reports for admin, but we'd need
# different logic for users - simplified here)
list_router = RBACRouter(
    prefix="/reports",
    tags=["Reports"],
    permissions={"report:read"},
    contexts=[],  # No context check - admin only effectively
)


@list_router.get("")
async def list_reports():
    """List all reports. Requires report:read with global scope (admin only)."""
    return [{"id": k, **v} for k, v in REPORTS.items()]


app.include_router(router)
app.include_router(list_router)


# =============================================================================
# Health Check (no auth required)
# =============================================================================
@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, port=18_000)
