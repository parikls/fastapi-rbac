import inspect
from collections.abc import Callable, Coroutine
from typing import Annotated, Any

from fastapi import Depends, Request

from fastapi_rbac.context import ContextualAuthz
from fastapi_rbac.errors import Forbidden
from fastapi_rbac.permissions import (
    has_global_permission,
    has_permission,
    resolve_grants,
)

# Type alias for context classes
ContextClass = type[ContextualAuthz]


async def _rbac_roles_dependency_placeholder(request: Request) -> set[str]:  # noqa: ARG001
    """Placeholder dependency for user roles.

    This placeholder is replaced at runtime via FastAPI's dependency_overrides
    mechanism when RBACAuthz is initialized. The roles_dependency provided to
    RBACAuthz will be used instead of this placeholder.
    """
    raise RuntimeError("RBACAuthz not configured with roles_dependency")


def create_authz_dependency(
    required_permissions: set[str],
    context_classes: list[ContextClass],
) -> Callable[..., Coroutine[Any, Any, None]]:
    """Create an authorization dependency that uses FastAPI's full DI for contexts.

    This function creates a FastAPI dependency that:
    1. Resolves a list of user roles via the injected roles_dependency
    2. Gets RBAC config from app.state.rbac
    3. Uses FastAPI's Depends(context_class) to instantiate each context
       - Context classes can use ANY FastAPI dependency patterns in __init__:
         - user: AuthUser (resolved via Depends)
         - request: Request (built-in)
         - org_id: str (from path parameter)
         - body: SomeModel (from request body)
         - db: Db (via Depends)
    4. Calls has_permissions() on each resolved context

    The roles_dependency is injected via FastAPI's dependency_overrides mechanism.
    When RBACAuthz is initialized with a roles_dependency, it overrides the
    _rbac_roles_dependency_placeholder with the provided dependency.

    Args:
        required_permissions: Set of permission strings required for access.
        context_classes: List of ContextualAuthz subclasses to check.

    Returns:
        An async dependency function for use with FastAPI's Depends().
    """
    # Build context parameters - each context class becomes a Depends(context_class)
    # FastAPI will resolve all __init__ parameters automatically
    if not required_permissions and not context_classes:
        raise RuntimeError("Endpoint must be protected with either permissions or contexts")

    context_params: list[inspect.Parameter] = []
    for i, ctx_class in enumerate(context_classes):
        param = inspect.Parameter(
            f"_fastapi_rbac_authz_ctx_{i}_",
            inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=Annotated[ctx_class, Depends(ctx_class)],
        )
        context_params.append(param)

    async def authz_dependency(
        request: Request,
        _rbac_roles_: Annotated[set[str], Depends(_rbac_roles_dependency_placeholder)],
        **kwargs: Any,
    ) -> None:
        """Authorization dependency that checks permissions and contexts."""
        rbac = getattr(request.app.state, "rbac", None)
        if rbac is None:
            raise RuntimeError("RBACAuthz not configured. Make sure to create an RBACAuthz instance with your app.")

        roles = _rbac_roles_
        if not roles:
            raise Forbidden("User has no roles")

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
                context = kwargs.get(f"_fastapi_rbac_authz_ctx_{i}_")
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
            "_rbac_roles_",
            inspect.Parameter.KEYWORD_ONLY,
            default=None,
            annotation=Annotated[set[str], Depends(_rbac_roles_dependency_placeholder)],
        ),
    ]

    new_sig = inspect.Signature(parameters=base_params + context_params)
    authz_dependency.__signature__ = new_sig  # type: ignore[attr-defined]
    return authz_dependency
