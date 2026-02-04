from fastapi_rbac import Forbidden


class TestExceptions:
    def test_forbidden_has_403_status_code(self) -> None:
        exc = Forbidden()
        assert exc.status_code == 403

    def test_forbidden_has_default_detail(self) -> None:
        exc = Forbidden()
        assert exc.detail == "Forbidden"

    def test_forbidden_accepts_custom_detail(self) -> None:
        exc = Forbidden(detail="Custom message")
        assert exc.detail == "Custom message"
