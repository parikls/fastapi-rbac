import inspect
from collections.abc import Awaitable, Callable, Coroutine
from typing import TYPE_CHECKING, Annotated, Any, TypeVar

from fastapi import Depends, Request

from fastapi_rbac.context import ContextualAuthz
from fastapi_rbac.exceptions import Forbidden
from fastapi_rbac.permissions import (
    has_global_permission,
    has_permission,
    resolve_grants,
)

if TYPE_CHECKING:
    from fastapi_rbac.core import RBACAuthz

UserT = TypeVar("UserT")

# Type alias for context classes
ContextClass = type[ContextualAuthz[Any]]


def RBACUser(request: Request) -> Any:
    """Get the current authenticated user for use in context classes.

    This dependency reads the user from request.state.user, which is set
    by the auth dependency created via create_auth_dependency().

    Usage in context classes:
        class MyContext(ContextualAuthz[User]):
            def __init__(
                self,
                user: Annotated[User, Depends(RBACUser)],
                request: Request,
            ):
                self.user = user
                self.request = request

            async def has_permissions(self) -> bool:
                # Check permissions based on user and request context
                return self.user.id in allowed_users

    Returns:
        The authenticated user object from request.state.user.

    Raises:
        Forbidden: If no user is found in request state.
    """
    user = getattr(request.state, "user", None)
    if user is None:
        raise Forbidden("User not authenticated")
    return user


def create_auth_dependency(
    rbac: "RBACAuthz[UserT]",  # noqa: ARG001 - kept for API consistency with RBACRouter
    user_dependency: Callable[..., UserT] | Callable[..., Awaitable[UserT]],
) -> Callable[..., Coroutine[Any, Any, UserT]]:
    """Create a typed auth dependency for use in endpoints.

    Args:
        rbac: The RBACAuthz configuration instance. Currently unused but kept for
            API consistency - RBACRouter stores the rbac reference for permission
            evaluation.
        user_dependency: A FastAPI dependency that returns the authenticated user.

    Returns:
        A dependency that can be used with Depends() in endpoint signatures.
    """

    async def auth_dependency(
        request: Request,
        user: Annotated[UserT, Depends(user_dependency)],
    ) -> UserT:
        # Store user in request state for authz dependency
        request.state.user = user
        return user

    return auth_dependency


async def _rbac_user_dependency_placeholder(request: Request) -> Any:
    """Placeholder dependency for user authentication.

    This placeholder is used in the authz_dependency signature and gets replaced
    at runtime via FastAPI's dependency_overrides mechanism when RBACAuthz is
    initialized with a user_dependency.

    If no user_dependency is configured, this falls back to reading from
    request.state.user (which must be set by the user's own auth mechanism).
    """
    return getattr(request.state, "user", None)


def create_authz_dependency(
    required_permissions: set[str],
    context_classes: list[ContextClass],
) -> Callable[..., Coroutine[Any, Any, None]]:
    """Create an authorization dependency that uses FastAPI's full DI for contexts.

    This function creates a FastAPI dependency that:
    1. Resolves user via the injected user_dependency (or placeholder fallback)
    2. Gets RBAC config from app.state.rbac
    3. Uses FastAPI's Depends(context_class) to instantiate each context
       - Context classes can use ANY FastAPI dependency patterns in __init__:
         - user: AuthUser (resolved via Depends)
         - request: Request (built-in)
         - org_id: str (from path parameter)
         - body: SomeModel (from request body)
         - db: Db (via Depends)
    4. Calls has_permissions() on each resolved context

    The user_dependency is injected via FastAPI's dependency_overrides mechanism.
    When RBACAuthz is initialized with a user_dependency, it overrides the
    _rbac_user_dependency_placeholder with the provided dependency.

    Args:
        required_permissions: Set of permission strings required for access.
        context_classes: List of ContextualAuthz subclasses to check.

    Returns:
        An async dependency function for use with FastAPI's Depends().
    """
    # Build context parameters - each context class becomes a Depends(context_class)
    # FastAPI will resolve all __init__ parameters automatically
    context_params: list[inspect.Parameter] = []
    for i, ctx_class in enumerate(context_classes):
        param = inspect.Parameter(
            f"_rbac_ctx_{i}_",
            inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=Annotated[ctx_class, Depends(ctx_class)],
        )
        context_params.append(param)

    async def authz_dependency(
        request: Request,
        _rbac_user_: Annotated[Any, Depends(_rbac_user_dependency_placeholder)],
        **kwargs: Any,
    ) -> None:
        """Authorization dependency that checks permissions and contexts."""
        # Get RBAC config from app state
        rbac = getattr(request.app.state, "rbac", None)
        if rbac is None:
            raise RuntimeError("RBACAuthz not configured. Make sure to create an RBACAuthz instance with your app.")

        # User is resolved by the injected user_dependency (or placeholder)
        user = _rbac_user_
        if user is None:
            raise Forbidden("User not authenticated")

        # Check permissions first
        if not required_permissions and not context_classes:
            raise RuntimeError("Endpoint must be protected with permissions or contexts")

        roles = rbac.get_roles(user)
        grants = resolve_grants(roles, rbac.permissions)

        if not grants:
            raise Forbidden()

        need_contextual_check = not required_permissions

        for required in required_permissions:
            if has_global_permission(grants, required):
                # Global permission - no need for contextual check for this permission
                continue

            need_contextual_check = True
            if not has_permission(grants, required):
                raise Forbidden()

        # Run contextual checks if needed
        # Context instances are already resolved by FastAPI via Depends(context_class)
        if need_contextual_check:
            for i in range(len(context_classes)):
                context = kwargs.get(f"_rbac_ctx_{i}_")
                if context is not None and not await context.has_permissions():
                    raise Forbidden()

    # Build the final signature with context params
    base_params = [
        inspect.Parameter(
            "request",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=Request,
        ),
        inspect.Parameter(
            "_rbac_user_",
            inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=Annotated[Any, Depends(_rbac_user_dependency_placeholder)],
        ),
    ]

    new_sig = inspect.Signature(parameters=base_params + context_params)
    authz_dependency.__signature__ = new_sig  # type: ignore[attr-defined]

    return authz_dependency


async def evaluate_permissions(
    user: Any,
    request: Request,
    rbac: "RBACAuthz[Any]",
    required_permissions: set[str],
    context_classes: list[ContextClass],
) -> None:
    """Directly evaluate permissions without FastAPI dependency injection.

    This function is useful for testing or when you need to check permissions
    outside of a FastAPI endpoint context. Unlike create_authz_dependency(),
    this function instantiates context classes directly with user and request.

    Args:
        user: The authenticated user object.
        request: The current HTTP request.
        rbac: The RBACAuthz configuration instance.
        required_permissions: Set of permission strings required for access.
        context_classes: List of ContextualAuthz subclasses to check.

    Raises:
        Forbidden: If the user does not have the required permissions.
        RuntimeError: If no permissions or contexts are specified.
    """
    if not required_permissions and not context_classes:
        raise RuntimeError("Endpoint must be protected with permissions or contexts")

    roles = rbac.get_roles(user)
    grants = resolve_grants(roles, rbac.permissions)

    if not grants:
        raise Forbidden()

    need_contextual_check = not required_permissions

    for required in required_permissions:
        if has_global_permission(grants, required):
            # Global permission - no need for contextual check for this permission
            continue

        need_contextual_check = True
        if not has_permission(grants, required):
            raise Forbidden()

    # Run contextual checks if needed
    # Instantiate context classes directly with user and request
    if need_contextual_check:
        for ctx_class in context_classes:
            # Context classes are expected to accept user and request in their __init__
            context = ctx_class(user=user, request=request)  # type: ignore[call-arg]
            if not await context.has_permissions():
                raise Forbidden()
