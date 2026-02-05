"""Schema introspection for RBAC UI visualization."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from fastapi_rbac.permissions import PermissionGrant

if TYPE_CHECKING:
    from fastapi import FastAPI
    from starlette.routing import BaseRoute

    from fastapi_rbac.core import RBACAuthz


class RoleSchema(BaseModel):
    """Schema for a role in the RBAC system."""

    name: str
    permissions: list[PermissionGrantSchema]


class PermissionGrantSchema(BaseModel):
    """Schema for a permission grant."""

    permission: str
    scope: str  # "global" or "contextual"


class PermissionSchema(BaseModel):
    """Schema for a permission with information about which roles grant it."""

    name: str
    granted_by: list[GrantedBySchema]


class GrantedBySchema(BaseModel):
    """Schema for role-to-permission grant relationship."""

    role: str
    scope: str  # "global" or "contextual"


class ContextSchema(BaseModel):
    """Schema for a context class."""

    name: str
    description: str | None
    used_by: list[str]  # List of endpoint identifiers (e.g., "GET /reports")


class EndpointSchema(BaseModel):
    """Schema for an endpoint with RBAC configuration."""

    path: str
    method: str
    summary: str | None
    description: str | None
    tags: list[str]
    permissions: list[str]
    contexts: list[str]


class UISchema(BaseModel):
    """Complete schema for RBAC UI visualization."""

    roles: list[RoleSchema]
    permissions: list[PermissionSchema]
    endpoints: list[EndpointSchema]
    contexts: list[ContextSchema]


def _extract_grants_from_role(
    role_name: str,
    grants: set[PermissionGrant],
) -> list[PermissionGrantSchema]:
    """Extract permission grant schemas from a role's grants."""
    return [
        PermissionGrantSchema(
            permission=grant.permission,
            scope=grant.scope.value,
        )
        for grant in grants
    ]


def _build_roles_schema(
    permissions_map: dict[str, set[PermissionGrant]],
) -> list[RoleSchema]:
    """Build role schemas from the permissions map."""
    roles = []
    for role_name, grants in sorted(permissions_map.items()):
        role = RoleSchema(
            name=role_name,
            permissions=_extract_grants_from_role(role_name, grants),
        )
        roles.append(role)
    return roles


def _build_permissions_schema(
    permissions_map: dict[str, set[PermissionGrant]],
) -> list[PermissionSchema]:
    """Build permission schemas showing which roles grant each permission."""
    # Collect all unique permissions and their granting roles
    permission_grants: dict[str, list[GrantedBySchema]] = {}

    for role_name, grants in permissions_map.items():
        for grant in grants:
            if grant.permission not in permission_grants:
                permission_grants[grant.permission] = []
            permission_grants[grant.permission].append(
                GrantedBySchema(
                    role=role_name,
                    scope=grant.scope.value,
                )
            )

    return [
        PermissionSchema(name=perm, granted_by=granted_by) for perm, granted_by in sorted(permission_grants.items())
    ]


def _get_rbac_metadata_from_route(route: BaseRoute) -> dict[str, Any] | None:
    """Extract RBAC metadata from a route's endpoint function.

    RBACRouter stores metadata in the endpoint's _rbac_metadata_ attribute.
    """
    endpoint = getattr(route, "endpoint", None)
    if endpoint is None:
        return None

    # Check if the endpoint has RBAC metadata attached
    return getattr(endpoint, "_rbac_metadata_", None)


def _build_endpoints_schema(app: FastAPI) -> tuple[list[EndpointSchema], dict[str, type]]:
    """Build endpoint schemas from the app's routes.

    Returns:
        Tuple of (endpoints, context_classes_map) where context_classes_map
        maps context class names to their actual class objects.
    """
    endpoints: list[EndpointSchema] = []
    context_classes: dict[str, type] = {}
    seen_endpoints: set[tuple[str, str]] = set()

    # Get all registered RBAC routers from RBACAuthz instance
    rbac_routers: list[tuple[str, Any]] = getattr(app.state.rbac, "routers", [])

    # Build metadata map from all registered routers
    metadata_map: dict[tuple[str, str], dict[str, Any]] = {}
    for prefix, router in rbac_routers:
        for (path, method), meta in router.endpoint_metadata.items():
            full_path = prefix + path
            metadata_map[(full_path, method)] = meta

    # Iterate through all app routes
    for route in app.routes:
        if not hasattr(route, "methods") or not hasattr(route, "path"):
            continue

        route_path = route.path
        methods = route.methods or {"GET"}

        for method in methods:
            if method == "HEAD":
                continue

            key = (route_path, method)
            if key in seen_endpoints:
                continue
            seen_endpoints.add(key)

            # Get metadata from router registry OR from endpoint directly
            # This fallback ensures endpoints work even if router was included
            # before RBACAuthz was initialized (bypassing _rbac_routers_ tracking)
            meta = metadata_map.get(key)
            if meta is None:
                # Fall back to checking endpoint metadata directly
                meta = _get_rbac_metadata_from_route(route)
            if not meta:
                meta = {}
            permissions = meta.get("permissions", set())
            contexts = meta.get("contexts", [])

            # Skip non-RBAC endpoints
            if not permissions and not contexts:
                continue

            # Track context classes for docstring extraction
            for ctx_class in contexts:
                context_classes[ctx_class.__name__] = ctx_class

            endpoint_schema = EndpointSchema(
                path=route_path,
                method=method,
                summary=getattr(route, "summary", None),
                description=getattr(route, "description", None),
                tags=list(getattr(route, "tags", []) or []),
                permissions=sorted(permissions),
                contexts=[ctx.__name__ for ctx in contexts],
            )
            endpoints.append(endpoint_schema)

    return endpoints, context_classes


def _build_contexts_schema(
    endpoints: list[EndpointSchema],
    context_classes: dict[str, type],
) -> list[ContextSchema]:
    """Build context schemas showing which endpoints use each context."""
    context_usage: dict[str, list[str]] = {}

    for endpoint in endpoints:
        endpoint_id = f"{endpoint.method} {endpoint.path}"
        for context_name in endpoint.contexts:
            if context_name not in context_usage:
                context_usage[context_name] = []
            context_usage[context_name].append(endpoint_id)

    return [
        ContextSchema(
            name=name,
            description=context_classes.get(name).__doc__ if name in context_classes else None,
            used_by=sorted(used_by),
        )
        for name, used_by in sorted(context_usage.items())
    ]


def build_ui_schema(app: FastAPI, rbac: RBACAuthz) -> UISchema:
    """Build the complete UI schema for RBAC visualization.

    Args:
        app: The FastAPI application instance.
        rbac: The RBACAuthz configuration.

    Returns:
        UISchema containing roles, permissions, endpoints, and contexts.
    """
    # Build endpoints first (we need them for context schema)
    endpoints, context_classes = _build_endpoints_schema(app)

    return UISchema(
        roles=_build_roles_schema(rbac.permissions),
        permissions=_build_permissions_schema(rbac.permissions),
        endpoints=endpoints,
        contexts=_build_contexts_schema(endpoints, context_classes),
    )
