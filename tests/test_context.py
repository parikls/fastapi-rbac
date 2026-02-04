import pytest
from fastapi import Request

from fastapi_rbac import ContextualAuthz


class User:
    def __init__(self, id: str, roles: set[str]) -> None:
        self.id = id
        self.roles = roles


class SimpleRoleContext(ContextualAuthz[User]):
    """Check if user has 'admin' role."""

    def __init__(self, user: User, request: Request) -> None:
        self.user = user
        self.request = request

    async def has_permissions(self) -> bool:
        return "admin" in self.user.roles


class TestContextualAuthz:
    def test_context_is_generic_over_user_type(self) -> None:
        # Type checking test - should not raise
        context: ContextualAuthz[User] = SimpleRoleContext(
            user=User(id="1", roles={"admin"}),
            request=None,  # type: ignore[arg-type]
        )
        assert context.user.id == "1"

    @pytest.mark.asyncio
    async def test_has_permissions_returns_bool(self) -> None:
        context = SimpleRoleContext(
            user=User(id="1", roles={"admin"}),
            request=None,  # type: ignore[arg-type]
        )
        result = await context.has_permissions()
        assert result is True

    @pytest.mark.asyncio
    async def test_has_permissions_returns_false(self) -> None:
        context = SimpleRoleContext(
            user=User(id="1", roles={"user"}),
            request=None,  # type: ignore[arg-type]
        )
        result = await context.has_permissions()
        assert result is False
