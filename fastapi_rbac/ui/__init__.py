"""UI module for RBAC authorization visualization."""

from fastapi_rbac.ui.routes import create_ui_router
from fastapi_rbac.ui.schema import build_ui_schema

__all__ = [
    "create_ui_router",
    "build_ui_schema",
]
