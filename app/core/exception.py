from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


class AppError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class InvalidClientError(AppError):
    pass


class InvalidGrantError(AppError):
    pass


class InvalidRequestError(AppError):
    pass


class UnauthorizedClientError(AppError):
    pass


class InvalidScopeError(AppError):
    pass


class NotFoundError(AppError):
    pass


class ConflictError(AppError):
    pass


class UnauthorizedError(AppError):
    pass


class ForbiddenError(AppError):
    pass


class ValidationError(AppError):
    pass


class RateLimitError(AppError):
    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class AccessDeniedError(AppError):
    pass


class UnsupportedMediaTypeError(AppError):
    pass


class EmailNotVerifiedError(AppError):
    pass


class ServerError(AppError):
    pass


class TemporarilyUnavailableError(AppError):
    pass


_STATUS_MAP: dict[type, int] = {
    # OAuth errors
    InvalidClientError: status.HTTP_401_UNAUTHORIZED,
    InvalidGrantError: status.HTTP_400_BAD_REQUEST,
    InvalidRequestError: status.HTTP_400_BAD_REQUEST,
    UnauthorizedClientError: status.HTTP_403_FORBIDDEN,
    InvalidScopeError: status.HTTP_400_BAD_REQUEST,
    AccessDeniedError: status.HTTP_403_FORBIDDEN,
    UnsupportedMediaTypeError: status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    ServerError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    TemporarilyUnavailableError: status.HTTP_503_SERVICE_UNAVAILABLE,
    # General errors
    NotFoundError: status.HTTP_404_NOT_FOUND,
    ConflictError: status.HTTP_409_CONFLICT,
    UnauthorizedError: status.HTTP_401_UNAUTHORIZED,
    ForbiddenError: status.HTTP_403_FORBIDDEN,
    ValidationError: status.HTTP_400_BAD_REQUEST,
    RateLimitError: status.HTTP_429_TOO_MANY_REQUESTS,
    EmailNotVerifiedError: status.HTTP_403_FORBIDDEN,
}

# OAuth2 standard error codes (RFC 6749 §5.2)
_OAUTH_ERROR_CODE: dict[type, str] = {
    InvalidClientError: "invalid_client",
    InvalidGrantError: "invalid_grant",
    InvalidRequestError: "invalid_request",
    UnauthorizedClientError: "unauthorized_client",
    InvalidScopeError: "invalid_scope",
    AccessDeniedError: "access_denied",
    ServerError: "server_error",
    TemporarilyUnavailableError: "temporarily_unavailable",
}

_GENERAL_ERROR_CODE: dict[type, str] = {
    NotFoundError: "not_found",
    ConflictError: "conflict",
    UnauthorizedError: "unauthorized",
    ForbiddenError: "forbidden",
    ValidationError: "validation_error",
    RateLimitError: "rate_limit",
    EmailNotVerifiedError: "email_not_verified",
    UnsupportedMediaTypeError: "unsupported_media_type",
}


def _make_response(
    status: int, error: str, description: str, headers: dict | None = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": error, "error_description": description},
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:

    @app.exception_handler(AppError)
    async def handle_app_error(_: Request, exc: AppError) -> JSONResponse:
        status = _STATUS_MAP.get(type(exc), 400)
        error_code = (
            _OAUTH_ERROR_CODE.get(type(exc))
            or _GENERAL_ERROR_CODE.get(type(exc))
            or type(exc).__name__.lower()
        )
        headers = None
        retry_after = getattr(exc, "retry_after", None)
        if retry_after is not None:
            headers = {"Retry-After": str(retry_after)}
        return _make_response(status, error_code, exc.message, headers)

    @app.exception_handler(Exception)
    async def handle_unhandled(_: Request, exc: Exception) -> JSONResponse:
        return _make_response(500, "server_error", "An unexpected error occurred.")
