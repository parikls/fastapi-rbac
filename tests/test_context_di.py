"""Tests for Context Dependency Injection."""

from typing import Annotated, Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_rbac import (
    Contextual,
    ContextualAuthz,
    RBACAuthz,
    RBACUser,
    create_auth_dependency,
)
from fastapi_rbac.router import RBACRouter


class User:
    def __init__(self, id: str, roles: set[str]) -> None:
        self.id = id
        self.roles = roles


def get_instructor_user() -> User:
    return User(id="instructor-1", roles={"instructor"})


# Fake database for testing dependency injection
class FakeDB:
    """A fake database that can be configured to allow or deny users."""

    def __init__(self, allowed_users: set[str] | None = None) -> None:
        self.allowed_users = allowed_users or set()

    def is_allowed(self, user_id: str) -> bool:
        return user_id in self.allowed_users


# Global DB instances for testing
_test_db: FakeDB | None = None


def get_db() -> FakeDB:
    """Dependency that returns the fake database."""
    if _test_db is None:
        raise RuntimeError("Test DB not configured")
    return _test_db


class DBContextAuthz(ContextualAuthz[User]):
    """Context that uses a database dependency to check permissions."""

    def __init__(
        self,
        user: Annotated[User, Depends(RBACUser)],
        request: Request,
        db: FakeDB = Depends(get_db),
    ) -> None:
        self.user = user
        self.request = request
        self.db = db

    async def has_permissions(self) -> bool:
        return self.db.is_allowed(self.user.id)


class TestContextReceivesInjectedDependencies:
    """Test that contexts receive injected dependencies via Depends()."""

    def test_context_receives_injected_dependencies(self) -> None:
        """Context with db: FakeDB = Depends(get_db) should receive the DB."""
        global _test_db
        # Configure DB to allow the instructor user
        _test_db = FakeDB(allowed_users={"instructor-1"})

        try:
            app = FastAPI()
            rbac: RBACAuthz[Any] = RBACAuthz(
                app,
                get_roles=lambda u: u.roles,
                permissions={
                    "instructor": {Contextual("report:read")},
                },
            )
            AuthUser = create_auth_dependency(rbac, user_dependency=get_instructor_user)

            router = RBACRouter(
                permissions={"report:read"},
                contexts=[DBContextAuthz],
            )

            @router.get("/reports")
            async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
                return {"user_id": user.id}

            app.include_router(router)

            client = TestClient(app)
            response = client.get("/reports")
            assert response.status_code == 200
            assert response.json() == {"user_id": "instructor-1"}
        finally:
            _test_db = None

    def test_context_with_failing_db_check(self) -> None:
        """Context should fail authorization when DB check fails."""
        global _test_db
        # Configure DB to NOT allow the instructor user
        _test_db = FakeDB(allowed_users=set())  # Empty set - no one allowed

        try:
            app = FastAPI()
            rbac: RBACAuthz[Any] = RBACAuthz(
                app,
                get_roles=lambda u: u.roles,
                permissions={
                    "instructor": {Contextual("report:read")},
                },
            )
            AuthUser = create_auth_dependency(rbac, user_dependency=get_instructor_user)

            router = RBACRouter(
                permissions={"report:read"},
                contexts=[DBContextAuthz],
            )

            @router.get("/reports")
            async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
                return {"user_id": user.id}

            app.include_router(router)

            client = TestClient(app)
            response = client.get("/reports")
            assert response.status_code == 403
        finally:
            _test_db = None


class TestContextDIWithMultipleDependencies:
    """Test contexts with multiple injected dependencies."""

    def test_context_with_multiple_dependencies(self) -> None:
        """Context with multiple Depends() parameters should receive all of them."""
        global _test_db
        _test_db = FakeDB(allowed_users={"instructor-1"})

        # Additional dependency for testing
        def get_org_id() -> str:
            return "org-123"

        class MultiDepContext(ContextualAuthz[User]):
            """Context with multiple dependencies."""

            def __init__(
                self,
                user: Annotated[User, Depends(RBACUser)],
                request: Request,
                db: FakeDB = Depends(get_db),
                org_id: str = Depends(get_org_id),
            ) -> None:
                self.user = user
                self.request = request
                self.db = db
                self.org_id = org_id

            async def has_permissions(self) -> bool:
                # Check both db and org_id are available
                return self.db.is_allowed(self.user.id) and self.org_id == "org-123"

        try:
            app = FastAPI()
            rbac: RBACAuthz[Any] = RBACAuthz(
                app,
                get_roles=lambda u: u.roles,
                permissions={
                    "instructor": {Contextual("report:read")},
                },
            )
            AuthUser = create_auth_dependency(rbac, user_dependency=get_instructor_user)

            router = RBACRouter(
                permissions={"report:read"},
                contexts=[MultiDepContext],
            )

            @router.get("/reports")
            async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
                return {"user_id": user.id}

            app.include_router(router)

            client = TestClient(app)
            response = client.get("/reports")
            assert response.status_code == 200
        finally:
            _test_db = None


class TestContextDIWithAsyncDependencies:
    """Test contexts with async dependencies."""

    def test_context_with_async_dependency(self) -> None:
        """Context with async Depends() should work correctly."""
        global _test_db
        _test_db = FakeDB(allowed_users={"instructor-1"})

        async def get_async_db() -> FakeDB:
            """Async dependency that returns the fake database."""
            if _test_db is None:
                raise RuntimeError("Test DB not configured")
            return _test_db

        class AsyncDBContext(ContextualAuthz[User]):
            """Context with async dependency."""

            def __init__(
                self,
                user: Annotated[User, Depends(RBACUser)],
                request: Request,
                db: FakeDB = Depends(get_async_db),
            ) -> None:
                self.user = user
                self.request = request
                self.db = db

            async def has_permissions(self) -> bool:
                return self.db.is_allowed(self.user.id)

        try:
            app = FastAPI()
            rbac: RBACAuthz[Any] = RBACAuthz(
                app,
                get_roles=lambda u: u.roles,
                permissions={
                    "instructor": {Contextual("report:read")},
                },
            )
            AuthUser = create_auth_dependency(rbac, user_dependency=get_instructor_user)

            router = RBACRouter(
                permissions={"report:read"},
                contexts=[AsyncDBContext],
            )

            @router.get("/reports")
            async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
                return {"user_id": user.id}

            app.include_router(router)

            client = TestClient(app)
            response = client.get("/reports")
            assert response.status_code == 200
        finally:
            _test_db = None


class TestContextDIDirectEvaluatePermissions:
    """Test create_authz_dependency function directly."""

    @pytest.mark.anyio
    async def test_create_authz_dependency_resolves_depends(self) -> None:
        """create_authz_dependency should resolve Depends() for context params."""
        from fastapi_rbac import create_authz_dependency

        global _test_db
        _test_db = FakeDB(allowed_users={"user-1"})

        try:
            app = FastAPI()
            RBACAuthz[Any](
                app,
                get_roles=lambda u: u.roles,
                permissions={
                    "user": {Contextual("resource:read")},
                },
            )

            authz_dep = create_authz_dependency(
                required_permissions={"resource:read"},
                context_classes=[DBContextAuthz],
            )

            # Verify the dependency function exists and has the right signature
            import inspect

            sig = inspect.signature(authz_dep)
            assert "request" in sig.parameters
        finally:
            _test_db = None
