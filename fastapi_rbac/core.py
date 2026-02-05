from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, FastAPI

from fastapi_rbac.dependencies import _rbac_roles_dependency_placeholder
from fastapi_rbac.permissions import PermissionGrant
from fastapi_rbac.router import RBACRouter
from fastapi_rbac.ui.routes import create_ui_router


class RBACAuthz:
    """Main RBAC authorization configuration.

    Attaches to a FastAPI application and provides authorization
    configuration for RBACRouter endpoints.

    Args:
        app: The FastAPI application instance.
        permissions: Mapping of role names to sets of permission grants.
        roles_dependency: FastAPI dependency that returns the user's roles as set[str].
            This dependency is injected into all RBAC-protected endpoints via
            FastAPI's dependency_overrides mechanism, and will be evaluated before RBAC checks
        ui_path: Optional path to mount the authorization UI (e.g., "/_rbac").
    """

    def __init__(
        self,
        app: FastAPI,
        permissions: dict[str, set[PermissionGrant]],
        roles_dependency: Callable[..., set[str]] | Callable[..., Awaitable[set[str]]],
        ui_path: str | None = None,
    ) -> None:
        self.app = app
        self.permissions = permissions
        self.roles_dependency = roles_dependency
        self.ui_path = ui_path

        # Instance attributes for state management
        self.routers: list[tuple[str, RBACRouter]] = []
        self._include_router_wrapped: bool = False

        # Attach to app state for access from routers
        app.state.rbac = self

        # Override the placeholder dependency with user's roles dependency
        # This allows the roles dependency to be injected into all
        # RBAC-protected endpoints with proper FastAPI dependency resolution
        app.dependency_overrides[_rbac_roles_dependency_placeholder] = roles_dependency
        self._wrap_app_include_router()

        if ui_path:
            self._mount_ui()

    def _wrap_app_include_router(self) -> None:
        """Wrap the app's include_router method to track RBACRouters."""
        if self._include_router_wrapped:
            return

        original_include_router = self.app.include_router
        self.app.include_router = self._create_wrapped_include_router(original_include_router)  # type: ignore[method-assign]
        self._include_router_wrapped = True

    def _create_wrapped_include_router(self, original_include_router: Callable[..., None]) -> Callable[..., None]:
        """Create a wrapped include_router that tracks RBACRouters."""

        def wrapped_include_router(
            router: APIRouter,
            *,
            prefix: str = "",
            **kwargs: Any,
        ) -> None:
            if isinstance(router, RBACRouter):
                self.routers.append((prefix, router))
            return original_include_router(router, prefix=prefix, **kwargs)

        return wrapped_include_router

    def _mount_ui(self) -> None:
        """Mount the authorization visualization UI."""
        if not self.ui_path:
            return

        ui_router = create_ui_router(self.ui_path)
        self.app.include_router(ui_router, prefix=self.ui_path)
