from enum import StrEnum


class PermissionScope(StrEnum):
    GLOBAL = "global"
    CONTEXTUAL = "contextual"


class PermissionGrant:
    """A permission grant with a scope (global or contextual)."""

    __slots__ = ("permission", "scope")

    def __init__(self, permission: str, scope: PermissionScope) -> None:
        self.permission = permission
        self.scope = scope

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PermissionGrant):
            return NotImplemented
        return self.permission == other.permission and self.scope == other.scope

    def __hash__(self) -> int:
        return hash((self.permission, self.scope))

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.permission!r})"


class Global(PermissionGrant):
    """A global permission grant - bypasses contextual checks."""

    def __init__(self, permission: str) -> None:
        super().__init__(permission, PermissionScope.GLOBAL)


class Contextual(PermissionGrant):
    """A contextual permission grant - requires context checks to pass."""

    def __init__(self, permission: str) -> None:
        super().__init__(permission, PermissionScope.CONTEXTUAL)


WILDCARD = "*"
SEPARATOR = ":"


def implies(held: str, required: str) -> bool:
    """Check if a held permission implies (grants) a required permission.

    Supports wildcards: 'report:*' implies 'report:read', 'report:delete', etc.
    Global wildcard '*' implies everything.
    """
    held_parts = held.split(SEPARATOR)
    required_parts = required.split(SEPARATOR)

    for i, held_part in enumerate(held_parts):
        if held_part == WILDCARD:
            return True
        if i >= len(required_parts):
            return False
        if held_part != required_parts[i]:
            return False

    return len(held_parts) == len(required_parts)


def resolve_grants(
    roles: set[str],
    permissions_map: dict[str, set[PermissionGrant]],
) -> list[PermissionGrant]:
    """Resolve all permission grants for a set of roles."""
    grants: list[PermissionGrant] = []
    for role in roles:
        for grant in permissions_map.get(role, set()):
            grants.append(grant)
    return grants


def has_permission(grants: list[PermissionGrant], required: str) -> bool:
    """Check if any grant satisfies the required permission."""
    return any(implies(grant.permission, required) for grant in grants)


def has_global_permission(grants: list[PermissionGrant], required: str) -> bool:
    """Check if any GLOBAL grant satisfies the required permission."""
    return any(grant.scope == PermissionScope.GLOBAL and implies(grant.permission, required) for grant in grants)
