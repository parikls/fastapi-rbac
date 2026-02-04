from fastapi import HTTPException


class Forbidden(HTTPException):
    """403 Forbidden - user lacks required permissions."""

    def __init__(self, detail: str = "Forbidden") -> None:
        super().__init__(status_code=403, detail=detail)
