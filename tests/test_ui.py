"""Tests for RBAC UI visualization."""

from typing import Annotated, Any

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_rbac import (
    Contextual,
    ContextualAuthz,
    Global,
    RBACAuthz,
    RBACRouter,
    RBACUser,
    create_auth_dependency,
)


class User:
    def __init__(self, id: str, roles: set[str]) -> None:
        self.id = id
        self.roles = roles


def get_admin_user() -> User:
    return User(id="admin-1", roles={"admin"})


class OrganizationContext(ContextualAuthz[User]):
    """Context for organization membership checks."""

    def __init__(self, user: Annotated[User, Depends(RBACUser)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return True


class TeamContext(ContextualAuthz[User]):
    """Context for team membership checks."""

    def __init__(self, user: Annotated[User, Depends(RBACUser)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return True


@pytest.fixture
def app_with_ui() -> FastAPI:
    """Create a FastAPI app with RBAC UI enabled."""
    app = FastAPI()

    rbac: RBACAuthz[Any] = RBACAuthz(
        app,
        get_roles=lambda u: u.roles,
        permissions={
            "admin": {Global("report:*"), Global("user:*")},
            "instructor": {Contextual("report:read"), Contextual("student:view")},
            "viewer": {Contextual("report:read")},
        },
        ui_path="/_rbac",
    )

    AuthUser = create_auth_dependency(rbac, user_dependency=get_admin_user)

    # Create router with RBAC permissions
    router = RBACRouter(
        permissions={"report:read"},
        contexts=[OrganizationContext],
    )

    @router.get("/reports", summary="List reports", tags=["reports"])
    async def list_reports(user: User = Depends(AuthUser)) -> dict[str, list[str]]:
        return {"reports": []}

    @router.post(
        "/reports",
        permissions={"report:create"},
        summary="Create report",
        tags=["reports"],
    )
    async def create_report(user: User = Depends(AuthUser)) -> dict[str, str]:
        return {"id": "new-report"}

    @router.get(
        "/reports/{id}",
        contexts=[TeamContext],
        summary="Get report by ID",
        tags=["reports"],
    )
    async def get_report(id: str, user: User = Depends(AuthUser)) -> dict[str, str]:
        return {"id": id}

    app.include_router(router, prefix="/api/v1")

    return app


@pytest.fixture
def client(app_with_ui: FastAPI) -> TestClient:
    return TestClient(app_with_ui)


class TestUIMounted:
    """Test that UI is mounted at configured path."""

    def test_ui_mounted_at_configured_path(self, client: TestClient) -> None:
        """GET to ui_path returns 200 with text/html."""
        response = client.get("/_rbac")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "RBAC" in response.text

    def test_ui_contains_cytoscape(self, client: TestClient) -> None:
        """UI HTML includes Cytoscape.js."""
        response = client.get("/_rbac")
        assert response.status_code == 200
        assert "cytoscape" in response.text.lower()

    def test_ui_contains_schema_url(self, client: TestClient) -> None:
        """UI HTML includes the schema URL."""
        response = client.get("/_rbac")
        assert response.status_code == 200
        assert "/_rbac/schema" in response.text


class TestUISchema:
    """Test the schema endpoint."""

    def test_ui_schema_endpoint_returns_json(self, client: TestClient) -> None:
        """GET to ui_path/schema returns JSON with roles, permissions, endpoints, contexts."""
        response = client.get("/_rbac/schema")
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]

        data = response.json()
        assert "roles" in data
        assert "permissions" in data
        assert "endpoints" in data
        assert "contexts" in data

    def test_ui_schema_contains_roles(self, client: TestClient) -> None:
        """schema.roles contains configured roles."""
        response = client.get("/_rbac/schema")
        data = response.json()

        role_names = {role["name"] for role in data["roles"]}
        assert "admin" in role_names
        assert "instructor" in role_names
        assert "viewer" in role_names

    def test_ui_schema_role_permissions(self, client: TestClient) -> None:
        """Role includes its permission grants with scope."""
        response = client.get("/_rbac/schema")
        data = response.json()

        admin_role = next(r for r in data["roles"] if r["name"] == "admin")
        admin_perms = {p["permission"] for p in admin_role["permissions"]}
        assert "report:*" in admin_perms
        assert "user:*" in admin_perms

        # Check scope is correct
        report_perm = next(p for p in admin_role["permissions"] if p["permission"] == "report:*")
        assert report_perm["scope"] == "global"

        instructor_role = next(r for r in data["roles"] if r["name"] == "instructor")
        instructor_perms = {p["permission"] for p in instructor_role["permissions"]}
        assert "report:read" in instructor_perms

        report_read_perm = next(p for p in instructor_role["permissions"] if p["permission"] == "report:read")
        assert report_read_perm["scope"] == "contextual"

    def test_ui_schema_contains_permissions(self, client: TestClient) -> None:
        """schema.permissions contains all permissions with granted_by info."""
        response = client.get("/_rbac/schema")
        data = response.json()

        perm_names = {p["name"] for p in data["permissions"]}
        assert "report:*" in perm_names
        assert "report:read" in perm_names
        assert "student:view" in perm_names

        # Check granted_by
        report_read = next(p for p in data["permissions"] if p["name"] == "report:read")
        granted_roles = {g["role"] for g in report_read["granted_by"]}
        assert "instructor" in granted_roles
        assert "viewer" in granted_roles

    def test_ui_schema_contains_endpoints(self, client: TestClient) -> None:
        """schema.endpoints contains RBACRouter endpoints with permissions and contexts."""
        response = client.get("/_rbac/schema")
        data = response.json()

        # Find endpoint by path and method
        endpoints_by_key = {(e["method"], e["path"]): e for e in data["endpoints"]}

        # Check list reports endpoint
        list_reports = endpoints_by_key.get(("GET", "/api/v1/reports"))
        assert list_reports is not None
        assert "report:read" in list_reports["permissions"]
        assert "OrganizationContext" in list_reports["contexts"]

        # Check create report endpoint (has overridden permissions)
        create_report = endpoints_by_key.get(("POST", "/api/v1/reports"))
        assert create_report is not None
        assert "report:create" in create_report["permissions"]
        assert "OrganizationContext" in create_report["contexts"]

        # Check get report endpoint (has merged contexts)
        get_report = endpoints_by_key.get(("GET", "/api/v1/reports/{id}"))
        assert get_report is not None
        assert "report:read" in get_report["permissions"]
        assert "OrganizationContext" in get_report["contexts"]
        assert "TeamContext" in get_report["contexts"]

    def test_ui_schema_endpoint_metadata(self, client: TestClient) -> None:
        """Endpoints include summary, description, and tags."""
        response = client.get("/_rbac/schema")
        data = response.json()

        list_endpoint = next(
            (e for e in data["endpoints"] if e["method"] == "GET" and e["path"] == "/api/v1/reports"),
            None,
        )
        assert list_endpoint is not None
        assert list_endpoint["summary"] == "List reports"
        assert "reports" in list_endpoint["tags"]

    def test_ui_schema_contains_contexts(self, client: TestClient) -> None:
        """schema.contexts contains context classes with used_by info."""
        response = client.get("/_rbac/schema")
        data = response.json()

        context_names = {c["name"] for c in data["contexts"]}
        assert "OrganizationContext" in context_names
        assert "TeamContext" in context_names

        # Check used_by
        org_context = next(c for c in data["contexts"] if c["name"] == "OrganizationContext")
        assert len(org_context["used_by"]) >= 1
        # OrganizationContext is used by all three endpoints
        assert any("/api/v1/reports" in used_by for used_by in org_context["used_by"])

    def test_ui_schema_context_has_description(self, client: TestClient) -> None:
        """schema.contexts includes description from docstring."""
        response = client.get("/_rbac/schema")
        data = response.json()

        org_context = next(c for c in data["contexts"] if c["name"] == "OrganizationContext")
        assert "description" in org_context
        assert org_context["description"] == "Context for organization membership checks."


class TestUINotMounted:
    """Test that UI is not mounted when ui_path is None."""

    def test_no_ui_when_path_not_set(self) -> None:
        """UI routes should not exist when ui_path is not set."""
        app = FastAPI()
        RBACAuthz[Any](
            app,
            get_roles=lambda u: u.roles,
            permissions={"admin": {Global("*")}},
            # ui_path not set
        )

        client = TestClient(app)
        response = client.get("/_rbac")
        assert response.status_code == 404

        response = client.get("/_rbac/schema")
        assert response.status_code == 404


class TestSchemaBuilding:
    """Test schema building edge cases."""

    def test_empty_permissions(self) -> None:
        """Schema works with empty permissions."""
        app = FastAPI()
        RBACAuthz[Any](
            app,
            get_roles=lambda u: u.roles,
            permissions={},
            ui_path="/_rbac",
        )

        client = TestClient(app)
        response = client.get("/_rbac/schema")
        assert response.status_code == 200

        data = response.json()
        assert data["roles"] == []
        assert data["permissions"] == []
        assert data["endpoints"] == []
        assert data["contexts"] == []

    def test_custom_ui_path(self) -> None:
        """UI can be mounted at custom path."""
        app = FastAPI()
        RBACAuthz[Any](
            app,
            get_roles=lambda u: u.roles,
            permissions={"admin": {Global("*")}},
            ui_path="/admin/authorization",
        )

        client = TestClient(app)
        response = client.get("/admin/authorization")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

        response = client.get("/admin/authorization/schema")
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]
