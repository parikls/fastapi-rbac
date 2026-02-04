from typing import Any

from fastapi import FastAPI

from fastapi_rbac import Contextual, Global, PermissionGrant, RBACAuthz


class TestRBACAuthzSetup:
    def test_rbac_attaches_to_app(self) -> None:
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda user: user.roles,
            permissions={
                "admin": {Global("*")},
            },
        )
        assert app.state.rbac is rbac

    def test_rbac_stores_permissions_map(self) -> None:
        app = FastAPI()
        permissions: dict[str, set[PermissionGrant]] = {
            "admin": {Global("report:*")},
            "user": {Contextual("report:read")},
        }
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda user: user.roles,
            permissions=permissions,
        )
        assert rbac.permissions == permissions

    def test_rbac_stores_get_roles_callable(self) -> None:
        app = FastAPI()

        def get_roles(user: Any) -> set[str]:
            return set(user.roles)

        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=get_roles,
            permissions={},
        )
        assert rbac.get_roles is get_roles

    def test_rbac_ui_path_default_none(self) -> None:
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda user: user.roles,
            permissions={},
        )
        assert rbac.ui_path is None

    def test_rbac_ui_path_can_be_set(self) -> None:
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda user: user.roles,
            permissions={},
            ui_path="/_rbac",
        )
        assert rbac.ui_path == "/_rbac"

    def test_rbac_ui_permissions_can_be_set(self) -> None:
        app = FastAPI()
        rbac: RBACAuthz[Any] = RBACAuthz(
            app,
            get_roles=lambda user: user.roles,
            permissions={},
            ui_path="/_rbac",
            ui_permissions={"admin:rbac:view"},
        )
        assert rbac.ui_permissions == {"admin:rbac:view"}
