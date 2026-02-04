from abc import ABC, abstractmethod
from typing import Generic, TypeVar

UserT = TypeVar("UserT")


class ContextualAuthz(ABC, Generic[UserT]):
    """Base class for contextual authorization checks.

    Subclasses are FastAPI dependencies - use standard Depends() for
    additional dependencies like database sessions.

    Example:
        class MyContext(ContextualAuthz[User]):
            def __init__(
                self,
                user: User,
                request: Request,
                db: AsyncSession = Depends(get_db),
            ):
                self.user = user
                self.request = request
                self.db = db

            async def has_permissions(self) -> bool:
                # Check access using self.user, self.request, self.db
                return True
    """

    user: UserT

    @abstractmethod
    async def has_permissions(self) -> bool:
        """Check if the user has permission in this context.

        Returns:
            True if access should be granted, False otherwise.
        """
        ...
