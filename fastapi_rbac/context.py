from abc import ABC, abstractmethod


class ContextualAuthz(ABC):
    """Base class for contextual authorization checks.

    Subclasses can use FastAPI dependencies in the __init__ method.

    Example:

    >>> class MyContext(ContextualAuthz):
    >>>     def __init__(
    >>>         self,
    >>>         user: Annotated[User, Depends(get_current_user)],  # your auth dep
    >>>         request: Request,  # fastapi dep
    >>>         db: AsyncSession = Depends(get_db),  # your database dep
    >>>     ):
    >>>         self.user = user
    >>>         self.request = request
    >>>         self.db = db
    >>>
    >>>     async def has_permissions(self) -> bool:
    >>>         # Check access using self.user, self.request, self.db
    >>>         return True
    """

    @abstractmethod
    async def has_permissions(self) -> bool:
        """Check if the user has permission in this context.

        Returns:
            True if access should be granted, False otherwise.
        """
        raise NotImplementedError()
