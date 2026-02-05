"""Tests for RBACRouter."""

from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, FastAPI, Request
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


def get_admin_user() -> User:
    return User(id="admin-1", roles={"admin"})


def get_admin_roles() -> set[str]:
    return {"admin"}


def get_instructor_user() -> User:
    return User(id="instructor-1", roles={"instructor"})


def get_instructor_roles() -> set[str]:
    return {"instructor"}


def get_no_role_user() -> User:
    return User(id="norole-1", roles=set())


def get_no_roles() -> set[str]:
    return set()


class AlwaysPassesContext(ContextualAuthz):
    def __init__(self, user: Annotated[User, Depends(get_admin_user)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return True


class AlwaysFailsContext(ContextualAuthz):
    def __init__(self, user: Annotated[User, Depends(get_admin_user)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return False


class InstructorOnlyContext(ContextualAuthz):
    def __init__(self, user: Annotated[User, Depends(get_instructor_user)], request: Request) -> None:
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
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:*")},
            },
            roles_dependency=get_admin_roles,
        )

        router = RBACRouter(permissions={"report:read"})

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_contextual_permission_with_passing_context(self) -> None:
        """User with contextual permission and passing context should access endpoint."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "instructor": {Contextual("report:read")},
            },
            roles_dependency=get_instructor_roles,
        )

        router = RBACRouter(
            permissions={"report:read"},
            contexts=[InstructorOnlyContext],
        )

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_contextual_permission_with_failing_context(self) -> None:
        """User with contextual permission but failing context should get 403."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "instructor": {Contextual("report:read")},
            },
            roles_dependency=get_instructor_roles,
        )

        router = RBACRouter(
            permissions={"report:read"},
            contexts=[AlwaysFailsContext],
        )

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403

    def test_no_permission_raises_forbidden(self) -> None:
        """User without required permission should get 403."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:*")},
            },
            roles_dependency=get_no_roles,
        )

        router = RBACRouter(permissions={"report:read"})

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403


class TestEndpointOverrides:
    def test_endpoint_permissions_override_router_permissions(self) -> None:
        """Endpoint-level permissions should completely replace router permissions."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("admin:*")},  # Admin can do admin stuff
                "instructor": {Contextual("report:read")},  # Instructor can read reports
            },
            roles_dependency=get_admin_roles,
        )

        # Router requires admin:* permissions
        router = RBACRouter(permissions={"admin:access"})

        # This endpoint OVERRIDES to require report:read instead
        @router.get("/reports", permissions={"report:read"})
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        # Admin should be denied because endpoint requires report:read,
        # not admin:access (which admin has)
        assert response.status_code == 403

    def test_endpoint_contexts_merge_with_router_contexts(self) -> None:
        """Endpoint-level contexts should merge with (add to) router contexts."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "instructor": {Contextual("report:read")},
            },
            roles_dependency=get_instructor_roles,
        )

        # Router has InstructorOnlyContext
        router = RBACRouter(
            permissions={"report:read"},
            contexts=[InstructorOnlyContext],
        )

        # Endpoint adds AlwaysFailsContext - should merge, not replace
        @router.get("/reports", contexts=[AlwaysFailsContext])
        async def get_reports() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        # Should be 403 because AlwaysFailsContext fails
        # (even though InstructorOnlyContext passes)
        assert response.status_code == 403


class TestWildcardValidation:
    def test_wildcard_in_endpoint_permission_raises_error(self) -> None:
        """Wildcard permissions in endpoint decorators should raise RuntimeError."""
        router = RBACRouter()

        # The error is raised when the decorator is applied
        with pytest.raises(RuntimeError, match="[Ww]ildcard"):

            @router.get("/reports", permissions={"report:*"})
            async def get_reports() -> dict[str, str]:
                return {"status": "ok"}

    def test_wildcard_in_router_permission_raises_error(self) -> None:
        """Wildcard permissions in router constructor should raise RuntimeError."""
        with pytest.raises(RuntimeError, match="[Ww]ildcard"):
            RBACRouter(permissions={"report:*"})

    def test_global_wildcard_in_endpoint_permission_raises_error(self) -> None:
        """Global wildcard '*' in endpoint permissions should raise RuntimeError."""
        router = RBACRouter()

        with pytest.raises(RuntimeError, match="[Ww]ildcard"):

            @router.get("/reports", permissions={"*"})
            async def get_reports() -> dict[str, str]:
                return {"status": "ok"}


class TestHTTPMethods:
    """Test that all HTTP method decorators work correctly."""

    def test_post_method(self) -> None:
        """POST method should work with permissions."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:create")},
            },
            roles_dependency=get_admin_roles,
        )

        router = RBACRouter(permissions={"report:create"})

        @router.post("/reports")
        async def create_report() -> dict[str, str]:
            return {"status": "ok"}

        app.include_router(router)

        client = TestClient(app)
        response = client.post("/reports")
        assert response.status_code == 200

    def test_put_method(self) -> None:
        """PUT method should work with permissions."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:update")},
            },
            roles_dependency=get_admin_roles,
        )

        router = RBACRouter(permissions={"report:update"})

        @router.put("/reports/{id}")
        async def update_report(id: str) -> dict[str, str]:
            return {"report_id": id}

        app.include_router(router)

        client = TestClient(app)
        response = client.put("/reports/123")
        assert response.status_code == 200

    def test_patch_method(self) -> None:
        """PATCH method should work with permissions."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:update")},
            },
            roles_dependency=get_admin_roles,
        )

        router = RBACRouter(permissions={"report:update"})

        @router.patch("/reports/{id}")
        async def patch_report(id: str) -> dict[str, str]:
            return {"report_id": id}

        app.include_router(router)

        client = TestClient(app)
        response = client.patch("/reports/123")
        assert response.status_code == 200

    def test_delete_method(self) -> None:
        """DELETE method should work with permissions."""
        app = FastAPI()
        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:delete")},
            },
            roles_dependency=get_admin_roles,
        )

        router = RBACRouter(permissions={"report:delete"})

        @router.delete("/reports/{id}")
        async def delete_report(id: str) -> dict[str, str]:
            return {"report_id": id}

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


class TestNoRoles:
    """Test behavior when user has no roles."""

    def test_empty_roles_raises_forbidden(self) -> None:
        """If roles dependency returns empty set, should raise Forbidden."""
        app = FastAPI()

        def get_empty_roles() -> set[str]:
            return set()

        RBACAuthz(
            app,
            permissions={
                "admin": {Global("report:*")},
            },
            roles_dependency=get_empty_roles,
        )

        router = RBACRouter(permissions={"report:read"})

        @router.get("/reports")
        async def get_reports() -> dict[str, str]:
            return {}

        app.include_router(router)

        client = TestClient(app)
        response = client.get("/reports")
        assert response.status_code == 403
