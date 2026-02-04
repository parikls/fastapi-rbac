# fastapi-rbac-authz

Role-based access control with contextual authorization for FastAPI.

## Installation

```bash
pip install fastapi-rbac-authz
```

## Quick Start

```python
from typing import Annotated
from fastapi import Depends, FastAPI
from fastapi_rbac import (
    RBACAuthz, RBACRouter, Global, Contextual, ContextualAuthz, RBACUser
)

# 1. Define your user model
class User:
    def __init__(self, user_id: str, roles: set[str]):
        self.user_id = user_id
        self.roles = roles

# 2. Define role permissions
PERMISSIONS = {
    "admin": {
        Global("report:*"),         # Admin can do anything with reports
    },
    "viewer": {
        Contextual("report:read"),  # Viewer needs context check
    },
}

# 3. Create a context check (for contextual permissions)
# All __init__ params are injected by FastAPI's DI system
class ReportAccessContext(ContextualAuthz[User]):
    def __init__(
        self,
        report_id: int,  # <-- Injected from path parameter
        user: Annotated[User, Depends(RBACUser)],
    ):
        self.user = user
        self.report_id = report_id

    async def has_permissions(self) -> bool:
        # Your logic: check if user can access this specific report
        allowed_reports = {1, 2, 3}  # e.g., query from database
        return self.report_id in allowed_reports

# 4. Create your app and configure RBAC
app = FastAPI()

async def get_current_user() -> User:
    # Your authentication logic here
    return User(user_id="user-1", roles={"viewer"})

RBACAuthz(
    app,
    get_roles=lambda u: u.roles,
    permissions=PERMISSIONS,
    user_dependency=get_current_user,
    ui_path="/_rbac",  # Optional: mount visualization UI
)

# 5. Create protected routes
router = RBACRouter(permissions={"report:read"}, contexts=[ReportAccessContext])

@router.get("/reports/{report_id}")
async def get_report(report_id: int):
    return {"report_id": report_id}

@router.post("/reports", permissions={"report:create"})  # Override permissions
async def create_report():
    return {"id": "new-report"}

app.include_router(router, prefix="/api")
```

## Permission Scopes

Permissions can be granted with two scopes:

### Global Scope

```python
Global("report:read")
```

Global permissions **bypass context checks entirely**. If a user has a global permission, they can access the resource without any additional validation. Use this for admin roles or service accounts that need unrestricted access.

### Contextual Scope

```python
Contextual("report:read")
```

Contextual permissions **require context checks to pass**. The user must have the permission AND the context check must return `True`. Use this for regular users who should only access resources they own or are members of.

### Example

```python
PERMISSIONS = {
    "admin": {
        Global("report:*"),         # Can access ALL reports, no questions asked
    },
    "user": {
        Contextual("report:read"),  # Can only read reports they have access to
        Contextual("report:create"),
    },
}
```

## Context Checks

Context checks are classes that implement fine-grained authorization logic. They're regular FastAPI dependencies, so you can inject any parameters (path params, query params, request body, database sessions, etc.).

```python
class ReportAccessContext(ContextualAuthz[User]):
    def __init__(
        self,
        report_id: int,  # Injected from path parameter
        user: Annotated[User, Depends(RBACUser)],
        db: Annotated[AsyncSession, Depends(get_db)],  # Database session
    ):
        self.user = user
        self.report_id = report_id
        self.db = db

    async def has_permissions(self) -> bool:
        # Query database to check if user can access this report
        report = await self.db.get(Report, self.report_id)
        return report is not None and report.owner_id == self.user.user_id
```

## Authorization Flow

When a request hits an RBAC-protected endpoint:

```
1. Authentication
   └── user_dependency runs → User object available

2. Permission Check
   └── Does user have ANY grant (global or contextual) for required permission?
       ├── No  → 403 Forbidden
       └── Yes → Continue

3. Scope Evaluation
   └── Is the grant Global?
       ├── Yes → Access granted (skip context checks)
       └── No  → Continue to context checks

4. Context Checks (only for Contextual grants)
   └── Run all context classes via FastAPI DI
       └── Do ALL contexts return True?
           ├── No  → 403 Forbidden
           └── Yes → Access granted

5. Endpoint Handler Executes
```

## Wildcard Permissions

Use wildcards to grant multiple permissions at once:

| Grant | Implies |
|-------|---------|
| `*` | Everything |
| `report:*` | `report:read`, `report:create`, `report:delete`, etc. |
| `report:metrics:*` | `report:metrics:view`, `report:metrics:export`, etc. |

```python
PERMISSIONS = {
    "admin": {Global("*")},              # Full access to everything
    "reporter": {Global("report:*")},    # Full access to reports only
}
```

## Running the Example

A complete runnable example is included in the `examples/` directory:

```bash
# Install dependencies
pip install fastapi-rbac-authz uvicorn

# Run the example
uvicorn examples.basic_app:app --reload
```

Then open your browser:

- **http://localhost:8000/docs** - OpenAPI docs to test the API
- **http://localhost:8000/_rbac** - Authorization visualization UI

### Test with different users

The example uses `X-Token` header for authentication:

```bash
# As admin (has Global("*") - full access)
curl -H "X-Token: admin-token" http://localhost:8000/reports
curl -H "X-Token: admin-token" http://localhost:8000/reports/1

# As user (has Contextual permissions - can only access own reports)
curl -H "X-Token: user-token" http://localhost:8000/reports/1  # OK (owns report 1)
curl -H "X-Token: user-token" http://localhost:8000/reports/3  # 403 (doesn't own report 3)

# As viewer (has Contextual read - can only read own reports)
curl -H "X-Token: viewer-token" http://localhost:8000/reports/1  # 403 (doesn't own any)
```

## Visualization UI

Mount the built-in visualization UI to explore your authorization schema:

```python
RBACAuthz(
    app,
    # ...
    ui_path="/_rbac",
)
```

Visit `/_rbac` to see an interactive graph showing:
- **Roles** and their permission grants
- **Permissions** with scope indicators (global/contextual)
- **Endpoints** and their required permissions
- **Context checks** and which endpoints use them

Double-click any node to isolate and explore its relationships.

### Screenshots

**Full authorization graph**

![Full Graph](https://github.com/user-attachments/assets/912826a4-63a6-4865-8ac7-707ce2746033)

**Role isolation view** - double-click a role to see what it can access

![Role Isolation](https://github.com/user-attachments/assets/392b8d06-aa10-433a-a7bf-bce1af02d9df)

**Endpoint isolation view** - double-click an endpoint to see who can access it

![Endpoint Isolation](https://github.com/user-attachments/assets/b0357fe1-d265-4aed-a4e3-ee439a370c46)
