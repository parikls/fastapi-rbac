from fastapi import HTTPException
from starlette.status import HTTP_403_FORBIDDEN


class Forbidden(HTTPException):
    def __init__(self, detail: str = "Forbidden") -> None:
        super().__init__(status_code=HTTP_403_FORBIDDEN, detail=detail)
