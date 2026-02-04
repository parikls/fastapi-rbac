"""FastAPI RBAC Authorization - Role-based access control with contextual authorization."""

__version__ = "0.1.0"

from fastapi_rbac.context import ContextualAuthz
from fastapi_rbac.core import RBACAuthz
from fastapi_rbac.dependencies import (
    RBACUser,
    create_auth_dependency,
    create_authz_dependency,
    evaluate_permissions,
)
from fastapi_rbac.exceptions import Forbidden
from fastapi_rbac.permissions import (
    Contextual,
    Global,
    PermissionGrant,
    PermissionScope,
)
from fastapi_rbac.router import RBACRouter

__all__ = [
    "RBACAuthz",
    "RBACRouter",
    "RBACUser",
    "ContextualAuthz",
    "Global",
    "Contextual",
    "PermissionGrant",
    "PermissionScope",
    "Forbidden",
    "create_auth_dependency",
    "create_authz_dependency",
    "evaluate_permissions",
]
