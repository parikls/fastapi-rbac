from fastapi_rbac.permissions import (
    Contextual,
    Global,
    PermissionGrant,
    PermissionScope,
    has_global_permission,
    has_permission,
    implies,
    resolve_grants,
)


class TestPermissionTypes:
    def test_global_creates_grant_with_global_scope(self) -> None:
        grant = Global("report:read")
        assert grant.permission == "report:read"
        assert grant.scope == PermissionScope.GLOBAL

    def test_contextual_creates_grant_with_contextual_scope(self) -> None:
        grant = Contextual("report:read")
        assert grant.permission == "report:read"
        assert grant.scope == PermissionScope.CONTEXTUAL

    def test_grants_are_hashable_for_sets(self) -> None:
        grants: set[PermissionGrant] = {Global("report:read"), Contextual("report:read")}
        assert len(grants) == 2

    def test_same_grants_are_equal(self) -> None:
        assert Global("report:read") == Global("report:read")
        assert Contextual("report:read") == Contextual("report:read")

    def test_different_scopes_are_not_equal(self) -> None:
        assert Global("report:read") != Contextual("report:read")


class TestWildcardMatching:
    def test_exact_match(self) -> None:
        assert implies("report:read", "report:read") is True

    def test_no_match_different_permission(self) -> None:
        assert implies("report:read", "report:delete") is False

    def test_wildcard_matches_any_suffix(self) -> None:
        assert implies("report:*", "report:read") is True
        assert implies("report:*", "report:delete") is True
        assert implies("report:*", "report:export:pdf") is True

    def test_wildcard_does_not_match_different_prefix(self) -> None:
        assert implies("report:*", "caseload:read") is False

    def test_global_wildcard_matches_everything(self) -> None:
        assert implies("*", "report:read") is True
        assert implies("*", "caseload:delete") is True
        assert implies("*", "org:tag:manage") is True

    def test_nested_wildcard(self) -> None:
        assert implies("org:tag:*", "org:tag:read") is True
        assert implies("org:tag:*", "org:tag:manage") is True
        assert implies("org:tag:*", "org:credit:read") is False

    def test_shorter_permission_does_not_match_longer(self) -> None:
        assert implies("report", "report:read") is False

    def test_longer_permission_does_not_match_shorter(self) -> None:
        assert implies("report:read:detailed", "report:read") is False


class TestPermissionResolution:
    def test_resolve_grants_from_roles(self) -> None:
        permissions_map: dict[str, set[PermissionGrant]] = {
            "admin": {Global("report:*")},
            "user": {Contextual("report:read")},
        }
        roles = {"admin", "user"}

        grants = resolve_grants(roles, permissions_map)

        assert Global("report:*") in grants
        assert Contextual("report:read") in grants

    def test_resolve_grants_unknown_role_ignored(self) -> None:
        permissions_map: dict[str, set[PermissionGrant]] = {
            "admin": {Global("report:*")},
        }
        roles = {"admin", "unknown"}

        grants = resolve_grants(roles, permissions_map)

        assert len(grants) == 1
        assert Global("report:*") in grants

    def test_has_permission_with_exact_match(self) -> None:
        grants: list[PermissionGrant] = [Contextual("report:read")]
        assert has_permission(grants, "report:read") is True

    def test_has_permission_with_wildcard(self) -> None:
        grants: list[PermissionGrant] = [Global("report:*")]
        assert has_permission(grants, "report:read") is True
        assert has_permission(grants, "report:delete") is True

    def test_has_permission_no_match(self) -> None:
        grants: list[PermissionGrant] = [Contextual("report:read")]
        assert has_permission(grants, "caseload:read") is False

    def test_has_global_permission_true(self) -> None:
        grants: list[PermissionGrant] = [Global("report:*"), Contextual("caseload:read")]
        assert has_global_permission(grants, "report:read") is True

    def test_has_global_permission_false_for_contextual(self) -> None:
        grants: list[PermissionGrant] = [Contextual("report:read")]
        assert has_global_permission(grants, "report:read") is False
