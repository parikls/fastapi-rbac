from fastapi import FastAPI

from fastapi_rbac import Contextual, Global, PermissionGrant, RBACAuthz


def get_test_roles() -> set[str]:
    """Dummy roles dependency for tests."""
    return set()


class TestRBACAuthzSetup:
    def test_rbac_attaches_to_app(self) -> None:
        app = FastAPI()
        rbac = RBACAuthz(
            app,
            permissions={
                "admin": {Global("*")},
            },
            roles_dependency=get_test_roles,
        )
        assert app.state.rbac is rbac

    def test_rbac_stores_permissions_map(self) -> None:
        app = FastAPI()
        permissions: dict[str, set[PermissionGrant]] = {
            "admin": {Global("report:*")},
            "user": {Contextual("report:read")},
        }
        rbac = RBACAuthz(
            app,
            permissions=permissions,
            roles_dependency=get_test_roles,
        )
        assert rbac.permissions == permissions

    def test_rbac_stores_roles_dependency(self) -> None:
        app = FastAPI()

        def custom_roles_dep() -> set[str]:
            return {"admin"}

        rbac = RBACAuthz(
            app,
            permissions={},
            roles_dependency=custom_roles_dep,
        )
        assert rbac.roles_dependency is custom_roles_dep

    def test_rbac_ui_path_default_none(self) -> None:
        app = FastAPI()
        rbac = RBACAuthz(
            app,
            permissions={},
            roles_dependency=get_test_roles,
        )
        assert rbac.ui_path is None

    def test_rbac_ui_path_can_be_set(self) -> None:
        app = FastAPI()
        rbac = RBACAuthz(
            app,
            permissions={},
            roles_dependency=get_test_roles,
            ui_path="/_rbac",
        )
        assert rbac.ui_path == "/_rbac"
