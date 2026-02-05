"""Tests for authorization dependency behavior."""

from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_rbac import (
    Contextual,
    ContextualAuthz,
    Global,
    RBACAuthz,
)
from fastapi_rbac.router import RBACRouter


class User:
    def __init__(self, id: str, roles: set[str]) -> None:
        self.id = id
        self.roles = roles


# Module-level user to allow tests to control which user is returned
_test_user: User | None = None


def get_test_user() -> User:
    if _test_user is None:
        raise RuntimeError("Test user not configured")
    return _test_user


def get_test_user_roles() -> set[str]:
    """Returns the roles for the current test user."""
    if _test_user is None:
        raise RuntimeError("Test user not configured")
    return _test_user.roles


class InstructorRoleContext(ContextualAuthz):
    def __init__(self, user: Annotated[User, Depends(get_test_user)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return "instructor" in self.user.roles


class AlwaysPassesContext(ContextualAuthz):
    def __init__(self, user: Annotated[User, Depends(get_test_user)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return True


class AlwaysFailsContext(ContextualAuthz):
    def __init__(self, user: Annotated[User, Depends(get_test_user)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return False


class TestAuthorizationDependency:
    """Test authorization behavior via RBACRouter and TestClient."""

    def test_raises_forbidden_when_no_grants(self) -> None:
        """User with unknown role should be forbidden."""
        global _test_user
        _test_user = User(id="user-1", roles={"unknown_role"})

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:*")},
            },
            roles_dependency=get_test_user_roles,
        )

        router = RBACRouter(permissions={"report:read"})

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403

    def test_passes_with_global_permission(self) -> None:
        """User with global permission should pass."""
        global _test_user
        _test_user = User(id="admin-1", roles={"admin"})

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:*")},
            },
            roles_dependency=get_test_user_roles,
        )

        router = RBACRouter(permissions={"report:read"})

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 200

    def test_raises_forbidden_when_no_permission(self) -> None:
        """User without required permission should be forbidden."""
        global _test_user
        _test_user = User(id="user-1", roles={"user"})

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "user": {Contextual("report:read")},  # User has report:read only
            },
            roles_dependency=get_test_user_roles,
        )

        # Require report:delete which user doesn't have
        router = RBACRouter(permissions={"report:delete"})

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403

    def test_runs_context_checks_for_contextual_permissions(self) -> None:
        """Contextual permission with passing context should pass."""
        global _test_user
        _test_user = User(id="user-1", roles={"instructor"})

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "instructor": {Contextual("report:read")},
            },
            roles_dependency=get_test_user_roles,
        )

        router = RBACRouter(
            permissions={"report:read"},
            contexts=[InstructorRoleContext],
        )

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 200

    def test_raises_forbidden_when_context_check_fails(self) -> None:
        """Contextual permission with failing context should be forbidden."""
        global _test_user
        # User has role but context will fail (user doesn't have "instructor" role)
        _test_user = User(id="user-1", roles={"user"})

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "user": {Contextual("report:read")},
            },
            roles_dependency=get_test_user_roles,
        )

        router = RBACRouter(
            permissions={"report:read"},
            contexts=[InstructorRoleContext],  # Will fail - user doesn't have instructor role
        )

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403

    def test_global_permission_bypasses_context_checks(self) -> None:
        """User with global permission should bypass context checks."""
        global _test_user
        _test_user = User(id="admin-1", roles={"admin"})

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:*")},
            },
            roles_dependency=get_test_user_roles,
        )

        router = RBACRouter(
            permissions={"report:read"},
            contexts=[AlwaysFailsContext],  # Would fail, but global permission bypasses
        )

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 200

    def test_runs_context_when_only_contexts_provided(self) -> None:
        """Contexts-only authorization should work when context passes."""
        global _test_user
        _test_user = User(id="user-1", roles={"instructor"})

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "instructor": {Contextual("report:read")},
            },
            roles_dependency=get_test_user_roles,
        )

        # No permissions, only contexts
        router = RBACRouter(contexts=[InstructorRoleContext])

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 200

    def test_fails_when_only_contexts_and_context_fails(self) -> None:
        """Contexts-only authorization should fail when context fails."""
        global _test_user
        _test_user = User(id="user-1", roles={"user"})  # Not an instructor

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "user": {Contextual("report:read")},
            },
            roles_dependency=get_test_user_roles,
        )

        # No permissions, only contexts - context will fail
        router = RBACRouter(contexts=[InstructorRoleContext])

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403

    def test_raises_forbidden_when_one_of_multiple_contexts_fails(self) -> None:
        """All context checks must pass."""
        global _test_user
        _test_user = User(id="user-1", roles={"instructor"})

        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "instructor": {Contextual("report:read")},
            },
            roles_dependency=get_test_user_roles,
        )

        # Multiple contexts - one passes, one fails
        router = RBACRouter(
            permissions={"report:read"},
            contexts=[AlwaysPassesContext, AlwaysFailsContext],
        )

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403
