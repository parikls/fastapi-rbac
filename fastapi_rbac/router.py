"""RBACRouter - FastAPI router with RBAC authorization."""

import inspect
from collections.abc import Callable
from functools import wraps
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from fastapi_rbac.context import ContextualAuthz
from fastapi_rbac.dependencies import create_authz_dependency
from fastapi_rbac.permissions import SEPARATOR, WILDCARD

ContextClass = type[ContextualAuthz]  # alias


def _validate_permissions(
    permissions: set[str] | None,
    location: str,
) -> None:
    """Various startup permissions validations"""
    if permissions is None:
        return
    for perm in permissions:
        if WILDCARD in perm:
            raise RuntimeError(
                f"Wildcard permissions are not allowed in {location}. "
                f"Found '{perm}'. Wildcards should only be used in role grants."
            )
        if SEPARATOR not in perm:
            raise RuntimeError(
                f"Each permission must decline at least one resource and one action. Found '{perm}' at {location}"
            )
        if perm.startswith(SEPARATOR) or perm.startswith(WILDCARD):
            raise RuntimeError(f"Permission must explicitly define resource. Found '{perm}' at {location}")


class RBACRouter(APIRouter):
    """FastAPI router with RBAC authorization support.

    Extends APIRouter to automatically inject authorization checks into endpoints.

    Args:
        permissions: Default permissions required for all endpoints on this router.
        contexts: Default contextual authorization classes for all endpoints.
        **kwargs: Additional arguments passed to APIRouter.

    Example:
        router = RBACRouter(
            permissions={"report:read"},
            contexts=[OrganizationMemberContext],
        )

        @router.get("/reports")
        async def get_reports(user: User = Depends(AuthUser)):
            return {"reports": [...]}

        # Override permissions for specific endpoint
        @router.post("/reports", permissions={"report:create"})
        async def create_report(user: User = Depends(AuthUser)):
            return {"id": "new-report"}
    """

    def __init__(
        self,
        *,
        permissions: set[str] | None = None,
        contexts: list[ContextClass] | None = None,
        **kwargs: Any,
    ) -> None:
        _validate_permissions(permissions, "router permissions")

        super().__init__(**kwargs)
        self.default_permissions: set[str] = permissions or set()
        self.default_contexts: list[ContextClass] = contexts or []
        self.endpoint_metadata: dict[tuple[str, str], dict[str, Any]] = {}

    def _resolve_permissions_and_contexts(
        self,
        path: str,
        method: str,
        permissions: set[str] | None,
        contexts: list[ContextClass] | None,
    ) -> tuple[set[str], list[ContextClass]]:
        """Resolve final permissions and contexts for an endpoint.

        Args:
            path: The endpoint path.
            method: The HTTP method (GET, POST, etc.).
            permissions: Endpoint-specific permissions (overrides router default).
            contexts: Endpoint-specific contexts (merges with router default).

        Returns:
            Tuple of (final_permissions, final_contexts).
        """
        _validate_permissions(permissions, "endpoint permissions")
        final_permissions = permissions if permissions is not None else self.default_permissions
        final_contexts = list(self.default_contexts)
        if contexts:
            final_contexts.extend(contexts)

        # Store metadata for UI introspection
        self.endpoint_metadata[(path, method)] = {
            "permissions": final_permissions,
            "contexts": final_contexts,
        }

        return final_permissions, final_contexts

    def _wrap_endpoint_with_authz(
        self,
        endpoint: Callable[..., Any],
        authz_dep: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Wrap an endpoint to add authz check after other dependencies.

        Creates a new function signature that includes the authz dependency
        as an annotated parameter, ensuring it runs after user auth dependencies.
        """
        # Get the original function's signature
        sig = inspect.signature(endpoint)
        params = list(sig.parameters.values())

        # Create authz dependency parameter - place it last so it runs after user deps
        authz_param = inspect.Parameter(
            "_rbac_authz_check_",
            inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=Annotated[None, Depends(authz_dep)],
        )

        # Build new parameters: original params + authz param
        new_params = params + [authz_param]
        new_sig = sig.replace(parameters=new_params)

        @wraps(endpoint)
        async def wrapped_async(
            *args: Any,
            _rbac_authz_check_: Annotated[None, Depends(authz_dep)] = None,
            **kwargs: Any,
        ) -> Any:
            return await endpoint(*args, **kwargs)

        wrapped_async.__signature__ = new_sig  # type: ignore[attr-defined]
        return wrapped_async

    def _add_route_with_authz(
        self,
        path: str,
        method: str,
        endpoint: Callable[..., Any],
        permissions: set[str] | None,
        contexts: list[ContextClass] | None,
        parent_method: Callable[..., Any],
        **kwargs: Any,
    ) -> Callable[..., Any]:
        """Add a route with authorization dependency.

        Args:
            path: The endpoint path.
            method: The HTTP method name (GET, POST, etc.).
            endpoint: The original endpoint function.
            permissions: Endpoint-specific permissions (overrides router default).
            contexts: Endpoint-specific contexts (merges with router default).
            parent_method: The parent APIRouter method to call.
            **kwargs: Additional route kwargs.

        Returns:
            The decorated endpoint.
        """
        final_permissions, final_contexts = self._resolve_permissions_and_contexts(path, method, permissions, contexts)

        # If there are permissions or contexts, wrap the endpoint
        if final_permissions or final_contexts:
            authz_dep = create_authz_dependency(final_permissions, final_contexts)
            endpoint = self._wrap_endpoint_with_authz(endpoint, authz_dep)

        # Attach RBAC metadata to endpoint for later introspection
        # This allows schema building to work even if router was included
        # before RBACAuthz was initialized (bypassing _rbac_routers_ tracking)
        endpoint._rbac_metadata_ = {  # type: ignore[attr-defined]
            "permissions": final_permissions,
            "contexts": final_contexts,
        }

        # Register the route
        result: Callable[..., Any] = parent_method(path, **kwargs)(endpoint)
        return result

    def get(  # type: ignore[override]
        self,
        path: str,
        *,
        permissions: set[str] | None = None,
        contexts: list[ContextClass] | None = None,
        **kwargs: Any,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a GET endpoint with optional permission overrides."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return self._add_route_with_authz(
                path, "GET", func, permissions, contexts, super(RBACRouter, self).get, **kwargs
            )

        return decorator

    def post(  # type: ignore[override]
        self,
        path: str,
        *,
        permissions: set[str] | None = None,
        contexts: list[ContextClass] | None = None,
        **kwargs: Any,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a POST endpoint with optional permission overrides."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return self._add_route_with_authz(
                path, "POST", func, permissions, contexts, super(RBACRouter, self).post, **kwargs
            )

        return decorator

    def put(  # type: ignore[override]
        self,
        path: str,
        *,
        permissions: set[str] | None = None,
        contexts: list[ContextClass] | None = None,
        **kwargs: Any,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a PUT endpoint with optional permission overrides."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return self._add_route_with_authz(
                path, "PUT", func, permissions, contexts, super(RBACRouter, self).put, **kwargs
            )

        return decorator

    def patch(  # type: ignore[override]
        self,
        path: str,
        *,
        permissions: set[str] | None = None,
        contexts: list[ContextClass] | None = None,
        **kwargs: Any,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a PATCH endpoint with optional permission overrides."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return self._add_route_with_authz(
                path, "PATCH", func, permissions, contexts, super(RBACRouter, self).patch, **kwargs
            )

        return decorator

    def delete(  # type: ignore[override]
        self,
        path: str,
        *,
        permissions: set[str] | None = None,
        contexts: list[ContextClass] | None = None,
        **kwargs: Any,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a DELETE endpoint with optional permission overrides."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return self._add_route_with_authz(
                path, "DELETE", func, permissions, contexts, super(RBACRouter, self).delete, **kwargs
            )

        return decorator
