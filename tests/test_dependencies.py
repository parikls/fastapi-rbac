from typing import Annotated, Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_rbac import (
    Contextual,
    ContextualAuthz,
    Forbidden,
    Global,
    RBACAuthz,
    RBACUser,
    create_auth_dependency,
)


class User:
    def __init__(self, id: str, roles: set[str]) -> None:
        self.id = id
        self.roles = roles


def get_current_user() -> User:
    return User(id="user-1", roles={"instructor"})


def get_admin_user() -> User:
    return User(id="admin-1", roles={"admin"})


class InstructorRoleContext(ContextualAuthz[User]):
    def __init__(self, user: Annotated[User, Depends(RBACUser)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return "instructor" in self.user.roles


class TestCreateAuthDependency:
    def test_returns_user_when_authorized(self) -> None:
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:*")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        @app.get("/test")
        async def endpoint(user: Annotated[User, Depends(AuthUser)]) -> dict[str, str]:
            return {"user_id": user.id}

        client = TestClient(app)
        # Note: This test doesn't go through RBACRouter so no permission check
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json() == {"user_id": "admin-1"}

    def test_stores_user_in_request_state(self) -> None:
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "instructor": {Contextual("report:read")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_current_user)

        captured_user: User | None = None

        @app.get("/test")
        async def endpoint(request: Request, user: Annotated[User, Depends(AuthUser)]) -> dict[str, str]:
            nonlocal captured_user
            captured_user = request.state.user
            return {"user_id": user.id}

        client = TestClient(app)
        response = client.get("/test")
        assert response.status_code == 200
        assert captured_user is not None
        assert captured_user.id == "user-1"

    def test_works_with_async_user_dependency(self) -> None:
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("*")},
            },
        )

        async def get_async_user() -> User:
            return User(id="async-user", roles={"admin"})

        AuthUser = create_auth_dependency(rbac, user_dependency=get_async_user)

        @app.get("/test")
        async def endpoint(user: Annotated[User, Depends(AuthUser)]) -> dict[str, str]:
            return {"user_id": user.id}

        client = TestClient(app)
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json() == {"user_id": "async-user"}


class TestEvaluatePermissions:
    @pytest.mark.anyio
    async def test_raises_forbidden_when_no_grants(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:*")},
            },
        )
        user = User(id="user-1", roles={"unknown_role"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        with pytest.raises(Forbidden):
            await evaluate_permissions(
                user=user,
                request=request,
                rbac=rbac,
                required_permissions={"report:read"},
                context_classes=[],
            )

    @pytest.mark.anyio
    async def test_passes_with_global_permission(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:*")},
            },
        )
        user = User(id="admin-1", roles={"admin"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        # Should not raise
        await evaluate_permissions(
            user=user,
            request=request,
            rbac=rbac,
            required_permissions={"report:read"},
            context_classes=[],
        )

    @pytest.mark.anyio
    async def test_raises_forbidden_when_no_permission(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "user": {Contextual("report:read")},
            },
        )
        user = User(id="user-1", roles={"user"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        # User has report:read but not report:delete
        with pytest.raises(Forbidden):
            await evaluate_permissions(
                user=user,
                request=request,
                rbac=rbac,
                required_permissions={"report:delete"},
                context_classes=[],
            )

    @pytest.mark.anyio
    async def test_runs_context_checks_for_contextual_permissions(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "instructor": {Contextual("report:read")},
            },
        )
        user = User(id="user-1", roles={"instructor"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        # Should pass because InstructorRoleContext returns True for instructors
        await evaluate_permissions(
            user=user,
            request=request,
            rbac=rbac,
            required_permissions={"report:read"},
            context_classes=[InstructorRoleContext],
        )

    @pytest.mark.anyio
    async def test_raises_forbidden_when_context_check_fails(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "user": {Contextual("report:read")},
            },
        )
        # User has the role but not "instructor" role required by context
        user = User(id="user-1", roles={"user"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        # Context check will fail because user doesn't have instructor role
        with pytest.raises(Forbidden):
            await evaluate_permissions(
                user=user,
                request=request,
                rbac=rbac,
                required_permissions={"report:read"},
                context_classes=[InstructorRoleContext],
            )

    @pytest.mark.anyio
    async def test_global_permission_bypasses_context_checks(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:*")},
            },
        )
        # Admin user - should bypass context check
        user = User(id="admin-1", roles={"admin"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        class AlwaysFailsContext(ContextualAuthz[User]):
            def __init__(self, user: User, request: Request) -> None:
                self.user = user
                self.request = request

            async def has_permissions(self) -> bool:
                return False

        # Should pass even with failing context because admin has global permission
        await evaluate_permissions(
            user=user,
            request=request,
            rbac=rbac,
            required_permissions={"report:read"},
            context_classes=[AlwaysFailsContext],
        )

    @pytest.mark.anyio
    async def test_raises_runtime_error_when_no_permissions_or_contexts(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("*")},
            },
        )
        user = User(id="admin-1", roles={"admin"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        with pytest.raises(RuntimeError, match="protected with permissions or contexts"):
            await evaluate_permissions(
                user=user,
                request=request,
                rbac=rbac,
                required_permissions=set(),
                context_classes=[],
            )

    @pytest.mark.anyio
    async def test_runs_context_when_only_contexts_provided(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "instructor": {Contextual("report:read")},
            },
        )
        user = User(id="user-1", roles={"instructor"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        # No required_permissions, only context_classes
        await evaluate_permissions(
            user=user,
            request=request,
            rbac=rbac,
            required_permissions=set(),
            context_classes=[InstructorRoleContext],
        )

    @pytest.mark.anyio
    async def test_fails_when_only_contexts_and_context_fails(self) -> None:
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "user": {Contextual("report:read")},
            },
        )
        user = User(id="user-1", roles={"user"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        # No required_permissions, only context_classes which will fail
        with pytest.raises(Forbidden):
            await evaluate_permissions(
                user=user,
                request=request,
                rbac=rbac,
                required_permissions=set(),
                context_classes=[InstructorRoleContext],
            )

    @pytest.mark.anyio
    async def test_raises_forbidden_when_some_permissions_pass_and_some_fail(self) -> None:
        """Test that ALL required permissions must be satisfied."""
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "user": {Contextual("report:read")},  # User only has report:read
            },
        )
        user = User(id="user-1", roles={"user"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        # User has report:read but not report:delete - should fail
        with pytest.raises(Forbidden):
            await evaluate_permissions(
                user=user,
                request=request,
                rbac=rbac,
                required_permissions={"report:read", "report:delete"},
                context_classes=[],
            )

    @pytest.mark.anyio
    async def test_raises_forbidden_when_one_of_multiple_contexts_fails(self) -> None:
        """Test that ALL context checks must pass."""
        from fastapi_rbac import evaluate_permissions

        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "instructor": {Contextual("report:read")},
            },
        )
        user = User(id="user-1", roles={"instructor"})

        scope: dict[str, str] = {"type": "http", "method": "GET", "path": "/test"}
        request = Request(scope)

        class AlwaysPassesContext(ContextualAuthz[User]):
            def __init__(self, user: User, request: Request) -> None:
                self.user = user
                self.request = request

            async def has_permissions(self) -> bool:
                return True

        class AlwaysFailsContext(ContextualAuthz[User]):
            def __init__(self, user: User, request: Request) -> None:
                self.user = user
                self.request = request

            async def has_permissions(self) -> bool:
                return False

        # First context passes, second fails - should raise Forbidden
        with pytest.raises(Forbidden):
            await evaluate_permissions(
                user=user,
                request=request,
                rbac=rbac,
                required_permissions={"report:read"},
                context_classes=[AlwaysPassesContext, AlwaysFailsContext],
            )
