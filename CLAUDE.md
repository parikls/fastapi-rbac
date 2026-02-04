# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FastAPI RBAC Authorization library providing role-based access control with contextual authorization for FastAPI applications. The package name is `fastapi-rbac` (import as `fastapi_rbac`).

## Development Commands

```bash
# Install dependencies
poetry install --with dev

# Run all tests
pytest -v tests/

# Run specific test file
pytest -v tests/test_integration.py

# Run specific test
pytest -k "test_name"

# Type checking (strict mode)
mypy fastapi_rbac

# Build package
poetry build
```

**IMPORTANT:** Always run pre-commit after making any code changes:
```bash
pre-commit run --all-files
```
This runs ruff (linting + formatting) and mypy (type checking on fastapi_rbac).

## Architecture

### Core Components

**RBACAuthz[UserT]** (`core.py`) - Main configuration class that attaches to FastAPI app. Configures role-to-permission mappings, user dependency injection, and optional visualization UI.

**RBACRouter** (`router.py`) - Extended APIRouter with permission decorators (`@router.get(permissions=..., contexts=...)`). Supports default permissions at router level with per-endpoint overrides. Stores endpoint metadata for UI introspection.

**Permission System** (`permissions.py`) - Two scopes: `Global` (bypasses context checks) and `Contextual` (requires context validation). Supports wildcard matching (`resource:*` matches `resource:read`). Wildcards only allowed in role grants, not endpoint requirements.

**ContextualAuthz[UserT]** (`context.py`) - Abstract base class for context-specific authorization. Subclasses are FastAPI dependencies that implement `async has_permissions() -> bool`. Supports full FastAPI DI in `__init__`. Context classes should use `Annotated[User, Depends(RBACUser)]` for the user parameter.

**Dependencies** (`dependencies.py`) - Creates FastAPI dependencies for auth and authz. Uses `dependency_overrides` pattern for user dependency injection. Manipulates function signatures dynamically via `inspect.Signature`.

**UI System** (`ui/`) - Cytoscape.js visualization mounted at configurable path. Introspects RBAC configuration to display role → permission → endpoint ← context relationships.

### Key Patterns

- **Request State**: User stored in `request.state.user`, RBAC config in `app.state.rbac`, routers in `app.state._rbac_routers_`
- **Metadata Tracking**: Endpoints store `_rbac_metadata_` attribute; routers track `endpoint_metadata[(path, method)]`
- **Permission Resolution**: Extract roles → resolve grants → check global permissions first → run contextual checks only if needed
- **Type Safety**: Strict mypy with full generics (`RBACAuthz[UserT]`, `ContextualAuthz[UserT]`)

### Public API (from `__init__.py`)

```python
RBACAuthz, RBACRouter, RBACUser, ContextualAuthz
Global, Contextual, PermissionGrant, PermissionScope
Forbidden, create_auth_dependency, create_authz_dependency, evaluate_permissions
```
