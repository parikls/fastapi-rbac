"""Tests for RBACRouter."""

from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_rbac import (
    Contextual,
    ContextualAuthz,
    Global,
    RBACAuthz,
    RBACUser,
    create_auth_dependency,
)
from fastapi_rbac.router import RBACRouter


class User:
    def __init__(self, id: str, roles: set[str]) -> None:
        self.id = id
        self.roles = roles


def get_admin_user() -> User:
    return User(id="admin-1", roles={"admin"})


def get_instructor_user() -> User:
    return User(id="instructor-1", roles={"instructor"})


def get_no_role_user() -> User:
    return User(id="norole-1", roles=set())


class AlwaysPassesContext(ContextualAuthz[User]):
    def __init__(self, user: Annotated[User, Depends(RBACUser)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return True


class AlwaysFailsContext(ContextualAuthz[User]):
    def __init__(self, user: Annotated[User, Depends(RBACUser)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return False


class InstructorOnlyContext(ContextualAuthz[User]):
    def __init__(self, user: Annotated[User, Depends(RBACUser)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return "instructor" in self.user.roles


class TestRBACRouterBasics:
    def test_router_inherits_from_apirouter(self) -> None:
        """RBACRouter should be a subclass of FastAPI's APIRouter."""
        router = RBACRouter()
        assert isinstance(router, APIRouter)

    def test_router_stores_default_permissions(self) -> None:
        """RBACRouter should store default permissions passed to constructor."""
        router = RBACRouter(permissions={"report:read", "report:write"})
        assert router.default_permissions == {"report:read", "report:write"}

    def test_router_stores_default_contexts(self) -> None:
        """RBACRouter should store default contexts passed to constructor."""
        router = RBACRouter(contexts=[AlwaysPassesContext, InstructorOnlyContext])
        assert router.default_contexts == [AlwaysPassesContext, InstructorOnlyContext]


class TestRBACRouterPermissionChecks:
    def test_global_permission_grants_access(self) -> None:
        """User with global permission should access the endpoint."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:*")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        router = RBACRouter(permissions={"report:read"})

        @router.get("/reports")
        async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 200
        assert response.json() == {"user_id": "admin-1"}

    def test_contextual_permission_with_passing_context(self) -> None:
        """User with contextual permission and passing context should access endpoint."""
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
            contexts=[InstructorOnlyContext],
        )

        @router.get("/reports")
        async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 200
        assert response.json() == {"user_id": "instructor-1"}

    def test_contextual_permission_with_failing_context(self) -> None:
        """User with contextual permission but failing context should get 403."""
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
            contexts=[AlwaysFailsContext],
        )

        @router.get("/reports")
        async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403

    def test_no_permission_raises_forbidden(self) -> None:
        """User without required permission should get 403."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:*")},
            },
        )
        # User has no roles, so no permissions
        AuthUser = create_auth_dependency(rbac, user_dependency=get_no_role_user)

        router = RBACRouter(permissions={"report:read"})

        @router.get("/reports")
        async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403


class TestEndpointOverrides:
    def test_endpoint_permissions_override_router_permissions(self) -> None:
        """Endpoint-level permissions should completely replace router permissions."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("admin:*")},  # Admin can do admin stuff
                "instructor": {Contextual("report:read")},  # Instructor can read reports
            },
        )
        # Use admin user who has admin:* but NOT report:read
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        # Router requires admin:* permissions
        router = RBACRouter(permissions={"admin:access"})

        # This endpoint OVERRIDES to require report:read instead
        @router.get("/reports", permissions={"report:read"})
        async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        # Admin should be denied because endpoint requires report:read,
        # not admin:access (which admin has)
        assert response.status_code == 403

    def test_endpoint_contexts_merge_with_router_contexts(self) -> None:
        """Endpoint-level contexts should merge with (add to) router contexts."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "instructor": {Contextual("report:read")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_instructor_user)

        # Router has InstructorOnlyContext
        router = RBACRouter(
            permissions={"report:read"},
            contexts=[InstructorOnlyContext],
        )

        # Endpoint adds AlwaysFailsContext - should merge, not replace
        @router.get("/reports", contexts=[AlwaysFailsContext])
        async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        # Should be 403 because AlwaysFailsContext fails
        # (even though InstructorOnlyContext passes)
        assert response.status_code == 403


class TestWildcardValidation:
    def test_wildcard_in_endpoint_permission_raises_error(self) -> None:
        """Wildcard permissions in endpoint decorators should raise RuntimeError."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("*")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        router = RBACRouter()

        # The error is raised when the decorator is applied
        with pytest.raises(RuntimeError, match="[Ww]ildcard"):

            @router.get("/reports", permissions={"report:*"})
            async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
                return {"user_id": user.id}

    def test_wildcard_in_router_permission_raises_error(self) -> None:
        """Wildcard permissions in router constructor should raise RuntimeError."""
        with pytest.raises(RuntimeError, match="[Ww]ildcard"):
            RBACRouter(permissions={"report:*"})

    def test_global_wildcard_in_endpoint_permission_raises_error(self) -> None:
        """Global wildcard '*' in endpoint permissions should raise RuntimeError."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("*")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        router = RBACRouter()

        with pytest.raises(RuntimeError, match="[Ww]ildcard"):

            @router.get("/reports", permissions={"*"})
            async def get_reports(user: User = Depends(AuthUser)) -> dict[str, str]:
                return {"user_id": user.id}


class TestHTTPMethods:
    """Test that all HTTP method decorators work correctly."""

    def test_post_method(self) -> None:
        """POST method should work with permissions."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:create")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        router = RBACRouter(permissions={"report:create"})

        @router.post("/reports")
        async def create_report(user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id}

        app.include_router(router)

        client = TestClient(app)
        response = client.post("/reports")
        assert response.status_code == 200

    def test_put_method(self) -> None:
        """PUT method should work with permissions."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:update")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        router = RBACRouter(permissions={"report:update"})

        @router.put("/reports/{id}")
        async def update_report(id: str, user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id, "report_id": id}

        app.include_router(router)

        client = TestClient(app)
        response = client.put("/reports/123")
        assert response.status_code == 200

    def test_patch_method(self) -> None:
        """PATCH method should work with permissions."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:update")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        router = RBACRouter(permissions={"report:update"})

        @router.patch("/reports/{id}")
        async def patch_report(id: str, user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id, "report_id": id}

        app.include_router(router)

        client = TestClient(app)
        response = client.patch("/reports/123")
        assert response.status_code == 200

    def test_delete_method(self) -> None:
        """DELETE method should work with permissions."""
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:delete")},
            },
        )
        AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

        router = RBACRouter(permissions={"report:delete"})

        @router.delete("/reports/{id}")
        async def delete_report(id: str, user: User = Depends(AuthUser)) -> dict[str, str]:
            return {"user_id": user.id, "report_id": id}

        app.include_router(router)

        client = TestClient(app)
        response = client.delete("/reports/123")
        assert response.status_code == 200


class TestMetadataStorage:
    """Test that RBACRouter stores metadata for UI introspection."""

    def test_router_stores_endpoint_metadata(self) -> None:
        """Router should store permission/context metadata for each endpoint."""
        router = RBACRouter(
            permissions={"report:read"},
            contexts=[InstructorOnlyContext],
        )

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {}

        @router.post("/reports", permissions={"report:create"})
        async def create_report() -> dict[str, str]:
            return {}

        # Check that metadata is accessible
        assert hasattr(router, "endpoint_metadata")
        assert len(router.endpoint_metadata) == 2

        # GET /reports should have router defaults
        get_meta = router.endpoint_metadata[("/reports", "GET")]
        assert get_meta["permissions"] == {"report:read"}
        assert get_meta["contexts"] == [InstructorOnlyContext]

        # POST /reports should have overridden permissions but merged contexts
        post_meta = router.endpoint_metadata[("/reports", "POST")]
        assert post_meta["permissions"] == {"report:create"}
        assert post_meta["contexts"] == [InstructorOnlyContext]  # Still has router context


class TestNoUserInRequest:
    """Test behavior when user is not set in request state."""

    def test_missing_user_raises_forbidden(self) -> None:
        """If user is not in request.state, should raise Forbidden."""
        app = FastAPI()
        RBACAuthz[Any](
            app,
            get_roles=lambda u: u.roles,
            permissions={
                "admin": {Global("report:*")},
            },
        )

        router = RBACRouter(permissions={"report:read"})

        # Don't use auth dependency, so user won't be in request.state
        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403
