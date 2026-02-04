from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from fastapi import APIRouter, FastAPI

from fastapi_rbac.dependencies import _rbac_user_dependency_placeholder
from fastapi_rbac.permissions import PermissionGrant

if TYPE_CHECKING:
    pass

UserT = TypeVar("UserT")


def _wrap_include_router(app: FastAPI, original_include_router: Callable[..., None]) -> Callable[..., None]:
    """Wrap FastAPI's include_router to track RBACRouters."""

    def wrapped_include_router(
        router: APIRouter,
        *,
        prefix: str = "",
        **kwargs: Any,
    ) -> None:
        # Import here to avoid circular import
        from fastapi_rbac.router import RBACRouter

        # Track RBAC routers in app state
        if isinstance(router, RBACRouter):
            if not hasattr(app.state, "_rbac_routers_"):
                app.state._rbac_routers_ = []
            app.state._rbac_routers_.append((prefix, router))

        # Call original method
        return original_include_router(router, prefix=prefix, **kwargs)

    return wrapped_include_router


class RBACAuthz(Generic[UserT]):
    """Main RBAC authorization configuration.

    Attaches to a FastAPI application and provides authorization
    configuration for RBACRouter endpoints.

    Args:
        app: The FastAPI application instance.
        get_roles: Callable that extracts role strings from a user object.
        permissions: Mapping of role names to sets of permission grants.
        user_dependency: Optional FastAPI dependency that returns the authenticated user.
            When provided, RBAC-protected endpoints will automatically run this dependency
            and store the result in request.state.user before authorization checks.
        ui_path: Optional path to mount the authorization UI (e.g., "/_rbac").
        ui_permissions: Optional set of permissions required to access the UI.
    """

    def __init__(
        self,
        app: FastAPI,
        get_roles: Callable[[UserT], set[str]],
        permissions: dict[str, set[PermissionGrant]],
        user_dependency: Callable[..., UserT] | Callable[..., Awaitable[UserT]] | None = None,
        ui_path: str | None = None,
        ui_permissions: set[str] | None = None,
    ) -> None:
        self.app = app
        self.get_roles = get_roles
        self.permissions = permissions
        self.user_dependency = user_dependency
        self.ui_path = ui_path
        self.ui_permissions = ui_permissions

        # Initialize router tracking list
        if not hasattr(app.state, "_rbac_routers_"):
            app.state._rbac_routers_ = []

        # Attach to app state for access from routers
        app.state.rbac = self

        # If user_dependency is provided, override the placeholder dependency
        # This allows the user's auth dependency to be injected into all
        # RBAC-protected endpoints with proper FastAPI dependency resolution
        if user_dependency is not None:
            app.dependency_overrides[_rbac_user_dependency_placeholder] = user_dependency

        # Wrap include_router to track RBAC routers
        self._wrap_app_include_router()

        # Mount UI if path specified
        if ui_path:
            self._mount_ui()

    def _wrap_app_include_router(self) -> None:
        """Wrap the app's include_router method to track RBACRouters."""
        # Only wrap if not already wrapped
        if hasattr(self.app, "_rbac_include_router_wrapped_"):
            return

        original_include_router = self.app.include_router
        self.app.include_router = _wrap_include_router(self.app, original_include_router)  # type: ignore[method-assign]
        self.app._rbac_include_router_wrapped_ = True  # type: ignore[attr-defined]

    def _mount_ui(self) -> None:
        """Mount the authorization visualization UI."""
        if not self.ui_path:
            return

        # Import here to avoid circular import
        from fastapi_rbac.ui.routes import create_ui_router

        ui_router = create_ui_router(self.ui_path)
        self.app.include_router(ui_router, prefix=self.ui_path)
