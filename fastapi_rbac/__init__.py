"""FastAPI RBAC Authorization - Role-based access control with contextual authorization."""

__version__ = "0.1.0"

from fastapi_rbac.context import ContextualAuthz
from fastapi_rbac.core import RBACAuthz
from fastapi_rbac.dependencies import create_authz_dependency
from fastapi_rbac.errors import Forbidden
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
    "ContextualAuthz",
    "Global",
    "Contextual",
    "PermissionGrant",
    "PermissionScope",
    "Forbidden",
    "create_authz_dependency",
]
