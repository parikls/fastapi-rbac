"""Comprehensive integration tests for fastapi-rbac-authz library.

This module tests the complete end-to-end behavior of the RBAC authorization library,
validating that all components work together correctly:
- RBACAuthz configuration
- RBACRouter with permissions and contexts
- Global vs Contextual permission grants
- Context bypassing for global permissions
- UI accessibility and schema generation
"""

from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_rbac import (
    Contextual,
    ContextualAuthz,
    Global,
    PermissionScope,
    RBACAuthz,
    RBACRouter,
)

# =============================================================================
# Test fixtures and helper classes
# =============================================================================


class User:
    """Simple user model for testing."""

    def __init__(self, id: str, roles: set[str]) -> None:
        self.id = id
        self.roles = roles


# User factories for dependency injection
_current_user: User | None = None


def get_current_user() -> User:
    """Get the current test user."""
    if _current_user is None:
        raise ValueError("Test user not set")
    return _current_user


def get_current_user_roles() -> set[str]:
    """Get the roles for the current test user."""
    if _current_user is None:
        raise ValueError("Test user not set")
    return _current_user.roles


def set_test_user(user: User) -> None:
    """Set the current test user for dependency injection."""
    global _current_user
    _current_user = user


class OrganizationMemberContext(ContextualAuthz):
    """Context check for organization membership.

    In a real application, this would check if the user is a member
    of the organization specified in the request path.
    """

    def __init__(self, user: Annotated[User, Depends(get_current_user)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        # Simulate: check if user has 'org_member' attribute or role
        return "org_member" in self.user.roles


class StudentAccessContext(ContextualAuthz):
    """Context check for student access.

    In a real application, this would verify the user has access
    to the specific student referenced in the request.
    """

    def __init__(self, user: Annotated[User, Depends(get_current_user)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        # Simulate: instructors can access their assigned students
        return "instructor" in self.user.roles


class AlwaysFailsContext(ContextualAuthz):
    """Context that always fails - for testing bypass scenarios."""

    def __init__(self, user: Annotated[User, Depends(get_current_user)], request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return False


# =============================================================================
# Integration test application setup
# =============================================================================


def create_integration_app() -> FastAPI:
    """Create a fully configured FastAPI app for integration testing."""
    app = FastAPI(title="RBAC Integration Test")

    # Configure RBAC with all role types
    RBACAuthz(
        app,
        permissions={
            # Superuser: Global("*") - bypasses ALL checks
            "superuser": {Global("*")},
            # Admin: Global("report:*") - bypasses context checks for report permissions
            "admin": {Global("report:*")},
            # Instructor: Contextual permissions - must pass context checks
            "instructor": {
                Contextual("report:read"),
                Contextual("student:view"),
            },
            # Viewer: Limited contextual permissions
            "viewer": {Contextual("report:read")},
        },
        roles_dependency=get_current_user_roles,
        ui_path="/_rbac",
    )

    # Reports router with permissions and contexts
    reports_router = RBACRouter(
        permissions={"report:read"},
        contexts=[OrganizationMemberContext],
    )

    @reports_router.get("/reports")
    async def list_reports() -> dict[str, str]:
        user = _current_user
        return {"status": "success", "user_id": user.id if user else "none"}

    @reports_router.get("/reports/{report_id}")
    async def get_report(report_id: str) -> dict[str, str]:
        user = _current_user
        return {"status": "success", "report_id": report_id, "user_id": user.id if user else "none"}

    @reports_router.post("/reports", permissions={"report:create"})
    async def create_report() -> dict[str, str]:
        user = _current_user
        return {"status": "created", "user_id": user.id if user else "none"}

    # Students router with multiple contexts
    students_router = RBACRouter(
        permissions={"student:view"},
        contexts=[OrganizationMemberContext, StudentAccessContext],
    )

    @students_router.get("/students/{student_id}")
    async def get_student(student_id: str) -> dict[str, str]:
        user = _current_user
        return {"status": "success", "student_id": student_id, "user_id": user.id if user else "none"}

    # Strict router - always fails context (for testing global bypass)
    strict_router = RBACRouter(
        permissions={"report:read"},
        contexts=[AlwaysFailsContext],
    )

    @strict_router.get("/strict-reports")
    async def get_strict_reports() -> dict[str, str]:
        user = _current_user
        return {"status": "success", "user_id": user.id if user else "none"}

    # Include all routers
    app.include_router(reports_router, prefix="/api/v1")
    app.include_router(students_router, prefix="/api/v1")
    app.include_router(strict_router, prefix="/api/v1")

    return app


@pytest.fixture
def app() -> FastAPI:
    """Create the integration test app."""
    return create_integration_app()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client for the integration app."""
    return TestClient(app)


# =============================================================================
# Test: Superuser bypasses all checks (Global("*"))
# =============================================================================


class TestSuperuserBypassesAllChecks:
    """Test that users with Global("*") bypass all permission and context checks."""

    def test_superuser_bypasses_all_permission_checks(self, client: TestClient) -> None:
        """User with Global('*') can access any endpoint regardless of required permissions."""
        set_test_user(User(id="superuser-1", roles={"superuser"}))

        # Access report:read endpoint
        response = client.get("/api/v1/reports")
        assert response.status_code == 200
        assert response.json()["user_id"] == "superuser-1"

        # Access report:create endpoint
        response = client.post("/api/v1/reports")
        assert response.status_code == 200

        # Access student:view endpoint
        response = client.get("/api/v1/students/student-123")
        assert response.status_code == 200

    def test_superuser_bypasses_context_checks(self, client: TestClient) -> None:
        """User with Global('*') bypasses all context checks, even failing ones."""
        # Superuser does NOT have org_member or instructor roles,
        # but should still bypass context checks
        set_test_user(User(id="superuser-1", roles={"superuser"}))

        # This endpoint has AlwaysFailsContext which always returns False
        # Superuser should bypass it
        response = client.get("/api/v1/strict-reports")
        assert response.status_code == 200
        assert response.json()["user_id"] == "superuser-1"

    def test_superuser_accesses_endpoint_with_multiple_contexts(self, client: TestClient) -> None:
        """Superuser bypasses even when multiple context checks would fail."""
        # Superuser without org_member or instructor roles
        set_test_user(User(id="superuser-1", roles={"superuser"}))

        # students endpoint requires OrganizationMemberContext AND StudentAccessContext
        # Both would fail, but superuser bypasses them
        response = client.get("/api/v1/students/student-456")
        assert response.status_code == 200
        assert response.json()["student_id"] == "student-456"


# =============================================================================
# Test: Admin bypasses context with Global("report:*")
# =============================================================================


class TestAdminBypassesContextWithGlobalPermission:
    """Test that users with Global("report:*") bypass contexts for report:* permissions."""

    def test_admin_bypasses_context_for_report_read(self, client: TestClient) -> None:
        """Admin with Global('report:*') bypasses context checks for report:read."""
        # Admin does NOT have org_member role
        set_test_user(User(id="admin-1", roles={"admin"}))

        # report:read endpoint with OrganizationMemberContext
        response = client.get("/api/v1/reports")
        assert response.status_code == 200
        assert response.json()["user_id"] == "admin-1"

    def test_admin_bypasses_failing_context_for_report_read(self, client: TestClient) -> None:
        """Admin bypasses AlwaysFailsContext for report:read."""
        set_test_user(User(id="admin-1", roles={"admin"}))

        # strict-reports has AlwaysFailsContext but requires report:read
        response = client.get("/api/v1/strict-reports")
        assert response.status_code == 200

    def test_admin_cannot_access_student_endpoints(self, client: TestClient) -> None:
        """Admin with only report:* cannot access student:view endpoints."""
        set_test_user(User(id="admin-1", roles={"admin"}))

        # student:view endpoint - admin doesn't have this permission
        response = client.get("/api/v1/students/student-123")
        assert response.status_code == 403


# =============================================================================
# Test: Instructor must pass all contexts (Contextual grants)
# =============================================================================


class TestInstructorMustPassAllContexts:
    """Test that users with Contextual permissions must pass all context checks."""

    def test_instructor_with_all_roles_succeeds(self, client: TestClient) -> None:
        """Instructor with required roles passes all context checks."""
        # Instructor with org_member role (passes OrganizationMemberContext)
        set_test_user(User(id="instructor-1", roles={"instructor", "org_member"}))

        response = client.get("/api/v1/reports")
        assert response.status_code == 200
        assert response.json()["user_id"] == "instructor-1"

    def test_instructor_without_org_member_fails(self, client: TestClient) -> None:
        """Instructor without org_member role fails OrganizationMemberContext."""
        # Instructor without org_member role
        set_test_user(User(id="instructor-1", roles={"instructor"}))

        response = client.get("/api/v1/reports")
        assert response.status_code == 403

    def test_instructor_fails_with_failing_context(self, client: TestClient) -> None:
        """Instructor cannot bypass AlwaysFailsContext."""
        set_test_user(User(id="instructor-1", roles={"instructor", "org_member"}))

        # AlwaysFailsContext will deny access
        response = client.get("/api/v1/strict-reports")
        assert response.status_code == 403

    def test_instructor_must_pass_all_contexts_for_students(self, client: TestClient) -> None:
        """Instructor must pass both OrganizationMemberContext and StudentAccessContext."""
        # Instructor with org_member role (passes both contexts)
        set_test_user(User(id="instructor-1", roles={"instructor", "org_member"}))

        response = client.get("/api/v1/students/student-789")
        assert response.status_code == 200
        assert response.json()["student_id"] == "student-789"

    def test_instructor_without_org_member_fails_student_endpoint(self, client: TestClient) -> None:
        """Instructor without org_member fails at OrganizationMemberContext."""
        # Has instructor (passes StudentAccessContext) but no org_member
        set_test_user(User(id="instructor-1", roles={"instructor"}))

        response = client.get("/api/v1/students/student-789")
        assert response.status_code == 403


# =============================================================================
# Test: Viewer role (limited contextual permissions)
# =============================================================================


class TestViewerRole:
    """Test viewer role with limited permissions."""

    def test_viewer_with_context_passes(self, client: TestClient) -> None:
        """Viewer with org_member can read reports."""
        set_test_user(User(id="viewer-1", roles={"viewer", "org_member"}))

        response = client.get("/api/v1/reports")
        assert response.status_code == 200

    def test_viewer_without_context_fails(self, client: TestClient) -> None:
        """Viewer without org_member fails context check."""
        set_test_user(User(id="viewer-1", roles={"viewer"}))

        response = client.get("/api/v1/reports")
        assert response.status_code == 403

    def test_viewer_cannot_create_reports(self, client: TestClient) -> None:
        """Viewer cannot access report:create endpoint."""
        set_test_user(User(id="viewer-1", roles={"viewer", "org_member"}))

        response = client.post("/api/v1/reports")
        assert response.status_code == 403

    def test_viewer_cannot_access_students(self, client: TestClient) -> None:
        """Viewer cannot access student endpoints (no student:view permission)."""
        set_test_user(User(id="viewer-1", roles={"viewer", "org_member"}))

        response = client.get("/api/v1/students/student-123")
        assert response.status_code == 403


# =============================================================================
# Test: UI accessibility
# =============================================================================


class TestUIIsAccessible:
    """Test that the RBAC UI is accessible at the configured path."""

    def test_ui_returns_html(self, client: TestClient) -> None:
        """UI at /_rbac returns 200 with text/html content type."""
        response = client.get("/_rbac")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_ui_contains_rbac_content(self, client: TestClient) -> None:
        """UI HTML contains RBAC-related content."""
        response = client.get("/_rbac")
        assert response.status_code == 200
        assert "RBAC" in response.text

    def test_ui_contains_schema_url(self, client: TestClient) -> None:
        """UI HTML references the schema endpoint."""
        response = client.get("/_rbac")
        assert "/_rbac/schema" in response.text


# =============================================================================
# Test: UI schema reflects routes
# =============================================================================


class TestUISchemaReflectsRoutes:
    """Test that the schema endpoint accurately reflects the RBAC configuration."""

    def test_schema_returns_json(self, client: TestClient) -> None:
        """Schema endpoint returns valid JSON with expected keys."""
        response = client.get("/_rbac/schema")
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]

        data = response.json()
        assert "roles" in data
        assert "permissions" in data
        assert "endpoints" in data
        assert "contexts" in data

    def test_schema_contains_all_roles(self, client: TestClient) -> None:
        """Schema contains all configured roles."""
        response = client.get("/_rbac/schema")
        data = response.json()

        role_names = {role["name"] for role in data["roles"]}
        assert "superuser" in role_names
        assert "admin" in role_names
        assert "instructor" in role_names
        assert "viewer" in role_names

    def test_schema_role_permissions_have_correct_scope(self, client: TestClient) -> None:
        """Role permissions include correct scope (global/contextual)."""
        response = client.get("/_rbac/schema")
        data = response.json()

        # Check superuser has global wildcard
        superuser = next(r for r in data["roles"] if r["name"] == "superuser")
        wildcard_perm = next(p for p in superuser["permissions"] if p["permission"] == "*")
        assert wildcard_perm["scope"] == "global"

        # Check admin has global report:*
        admin = next(r for r in data["roles"] if r["name"] == "admin")
        report_perm = next(p for p in admin["permissions"] if p["permission"] == "report:*")
        assert report_perm["scope"] == "global"

        # Check instructor has contextual permissions
        instructor = next(r for r in data["roles"] if r["name"] == "instructor")
        report_read = next(p for p in instructor["permissions"] if p["permission"] == "report:read")
        assert report_read["scope"] == "contextual"

    def test_schema_contains_endpoints(self, client: TestClient) -> None:
        """Schema contains RBAC-protected endpoints with their configuration."""
        response = client.get("/_rbac/schema")
        data = response.json()

        # Find endpoints by path/method
        endpoints_by_key = {(e["method"], e["path"]): e for e in data["endpoints"]}

        # Check reports endpoints
        assert ("GET", "/api/v1/reports") in endpoints_by_key
        reports_get = endpoints_by_key[("GET", "/api/v1/reports")]
        assert "report:read" in reports_get["permissions"]
        assert "OrganizationMemberContext" in reports_get["contexts"]

        # Check students endpoint
        assert ("GET", "/api/v1/students/{student_id}") in endpoints_by_key
        students_get = endpoints_by_key[("GET", "/api/v1/students/{student_id}")]
        assert "student:view" in students_get["permissions"]
        assert "OrganizationMemberContext" in students_get["contexts"]
        assert "StudentAccessContext" in students_get["contexts"]

    def test_schema_contains_contexts(self, client: TestClient) -> None:
        """Schema contains context classes with usage information."""
        response = client.get("/_rbac/schema")
        data = response.json()

        context_names = {c["name"] for c in data["contexts"]}
        assert "OrganizationMemberContext" in context_names
        assert "StudentAccessContext" in context_names
        assert "AlwaysFailsContext" in context_names

        # Check usage info
        org_context = next(c for c in data["contexts"] if c["name"] == "OrganizationMemberContext")
        assert len(org_context["used_by"]) >= 2  # Used by multiple endpoints


# =============================================================================
# Test: Library exports
# =============================================================================


class TestLibraryExports:
    """Test that all required exports are available from the package."""

    def test_rbac_authz_exported(self) -> None:
        """RBACAuthz is exported."""
        from fastapi_rbac import RBACAuthz

        assert RBACAuthz is not None

    def test_rbac_router_exported(self) -> None:
        """RBACRouter is exported."""
        from fastapi_rbac import RBACRouter

        assert RBACRouter is not None

    def test_global_exported(self) -> None:
        """Global is exported."""
        from fastapi_rbac import Global

        assert Global is not None
        # Verify it works
        grant = Global("test:permission")
        assert grant.permission == "test:permission"
        assert grant.scope == PermissionScope.GLOBAL

    def test_contextual_exported(self) -> None:
        """Contextual is exported."""
        from fastapi_rbac import Contextual

        assert Contextual is not None
        # Verify it works
        grant = Contextual("test:permission")
        assert grant.permission == "test:permission"
        assert grant.scope == PermissionScope.CONTEXTUAL

    def test_permission_grant_exported(self) -> None:
        """PermissionGrant is exported."""
        from fastapi_rbac import PermissionGrant

        assert PermissionGrant is not None

    def test_permission_scope_exported(self) -> None:
        """PermissionScope is exported."""
        from fastapi_rbac import PermissionScope

        assert PermissionScope is not None
        # PermissionScope is a StrEnum, so we compare using str()
        assert str(PermissionScope.GLOBAL) == "global"
        assert str(PermissionScope.CONTEXTUAL) == "contextual"

    def test_contextual_authz_exported(self) -> None:
        """ContextualAuthz is exported."""
        from fastapi_rbac import ContextualAuthz

        assert ContextualAuthz is not None

    def test_create_authz_dependency_exported(self) -> None:
        """create_authz_dependency is exported."""
        from fastapi_rbac import create_authz_dependency

        assert create_authz_dependency is not None
        assert callable(create_authz_dependency)

    def test_forbidden_exported(self) -> None:
        """Forbidden exception is exported."""
        from fastapi_rbac import Forbidden

        assert Forbidden is not None
        # Verify it works
        exc = Forbidden("Test message")
        assert exc.status_code == 403
        assert exc.detail == "Test message"


# =============================================================================
# Test: No roles user
# =============================================================================


class TestNoRolesUser:
    """Test behavior when user has no roles."""

    def test_user_with_no_roles_is_forbidden(self, client: TestClient) -> None:
        """User with no roles cannot access protected endpoints."""
        set_test_user(User(id="noroles-1", roles=set()))

        response = client.get("/api/v1/reports")
        assert response.status_code == 403

    def test_user_with_unknown_role_is_forbidden(self, client: TestClient) -> None:
        """User with unknown roles cannot access protected endpoints."""
        set_test_user(User(id="unknown-1", roles={"unknown_role"}))

        response = client.get("/api/v1/reports")
        assert response.status_code == 403
