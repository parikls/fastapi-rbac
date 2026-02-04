"""Routes for RBAC UI visualization."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from fastapi_rbac.ui.schema import build_ui_schema

if TYPE_CHECKING:
    from fastapi_rbac.core import RBACAuthz

# Path to static files
STATIC_DIR = Path(__file__).parent / "static"


def create_ui_router(ui_path: str) -> APIRouter:
    """Create a router for the RBAC UI visualization.

    Args:
        ui_path: The base path for the UI (e.g., "/_rbac").

    Returns:
        An APIRouter with routes for the UI HTML and schema JSON.
    """
    router = APIRouter(tags=["rbac-ui"])

    @router.get(
        "",
        response_class=HTMLResponse,
        summary="RBAC Visualization UI",
        description="Interactive visualization of roles, permissions, and endpoints.",
        include_in_schema=False,
    )
    async def get_ui(request: Request) -> HTMLResponse:
        """Serve the RBAC visualization HTML page."""
        html_file = STATIC_DIR / "index.html"
        if not html_file.exists():
            return HTMLResponse(
                content="<html><body><h1>UI not found</h1></body></html>",
                status_code=500,
            )

        content = html_file.read_text()
        # Replace placeholder with actual schema endpoint path
        schema_url = f"{ui_path}/schema"
        content = content.replace("{{SCHEMA_URL}}", schema_url)

        return HTMLResponse(content=content)

    @router.get(
        "/schema",
        response_class=JSONResponse,
        summary="RBAC Schema",
        description="JSON schema of all roles, permissions, endpoints, and contexts.",
        include_in_schema=False,
    )
    async def get_schema(request: Request) -> JSONResponse:
        """Return the RBAC schema as JSON."""
        rbac: RBACAuthz[Any] = request.app.state.rbac
        schema = build_ui_schema(request.app, rbac)
        return JSONResponse(content=schema.model_dump())

    return router
