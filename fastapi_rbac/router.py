"""RBACRouter - FastAPI router with RBAC authorization."""

import inspect
from collections.abc import Callable
from functools import wraps
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from fastapi_rbac.context import ContextualAuthz
from fastapi_rbac.dependencies import create_authz_dependency
from fastapi_rbac.permissions import WILDCARD

# Type alias for context classes
ContextClass = type[ContextualAuthz[Any]]


def _contains_wildcard(permission: str) -> bool:
    """Check if a permission contains a wildcard."""
    return WILDCARD in permission


def _validate_permissions(permissions: set[str] | None, location: str) -> None:
    """Validate that permissions don't contain wildcards.

    Args:
        permissions: Set of permission strings to validate.
        location: Description of where the permissions are defined (for error message).

    Raises:
        RuntimeError: If any permission contains a wildcard.
    """
    if permissions is None:
        return
    for perm in permissions:
        if _contains_wildcard(perm):
            raise RuntimeError(
                f"Wildcard permissions are not allowed in {location}. "
                f"Found '{perm}'. Wildcards should only be used in role grants."
            )


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
        # Validate no wildcards in router-level permissions
        _validate_permissions(permissions, "router permissions")

        super().__init__(**kwargs)
        self.default_permissions: set[str] = permissions or set()
        self.default_contexts: list[ContextClass] = contexts or []
        self.endpoint_metadata: dict[tuple[str, str], dict[str, Any]] = {}

    def _create_authz_dependency(
        self,
        permissions: set[str],
        contexts: list[ContextClass],
    ) -> Callable[..., Any]:
        """Create an authorization dependency for an endpoint.

        This dependency will be injected into the endpoint and will check
        permissions before the endpoint handler is called.

        Uses create_authz_dependency from dependencies.py which supports
        resolving Depends() parameters in context classes.
        """
        return create_authz_dependency(
            required_permissions=permissions,
            context_classes=contexts,
        )

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
        # Validate no wildcards in endpoint-level permissions
        _validate_permissions(permissions, "endpoint permissions")

        # Resolve final permissions: endpoint overrides router
        final_permissions = permissions if permissions is not None else self.default_permissions

        # Resolve final contexts: endpoint merges with router
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

        # Determine if endpoint is async
        is_async = inspect.iscoroutinefunction(endpoint)

        if is_async:

            @wraps(endpoint)
            async def wrapped_async(
                *args: Any,
                _rbac_authz_check_: Annotated[None, Depends(authz_dep)] = None,
                **kwargs: Any,
            ) -> Any:
                return await endpoint(*args, **kwargs)

            wrapped_async.__signature__ = new_sig  # type: ignore[attr-defined]
            return wrapped_async
        else:

            @wraps(endpoint)
            def wrapped_sync(
                *args: Any,
                _rbac_authz_check_: Annotated[None, Depends(authz_dep)] = None,
                **kwargs: Any,
            ) -> Any:
                return endpoint(*args, **kwargs)

            wrapped_sync.__signature__ = new_sig  # type: ignore[attr-defined]
            return wrapped_sync

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
            authz_dep = self._create_authz_dependency(final_permissions, final_contexts)
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
