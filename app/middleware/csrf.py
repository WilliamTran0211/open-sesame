import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import get_settings

logger = logging.getLogger("open_sesame_logger")

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _origin_allowed(request: Request) -> bool:
    allowed = set(get_settings().BACKEND_CORS_ORIGINS)
    origin = request.headers.get("origin")
    if origin:
        return origin in allowed
    referer = request.headers.get("referer")
    if referer:
        return any(referer.startswith(o) for o in allowed)
    # No Origin/Referer, reject.
    return False


class CSRFMiddleware(BaseHTTPMiddleware):
    # CSRF cho các request thay đổi trạng thái dùng cookie.
    # Origin/Referer phải khớp BACKEND_CORS_ORIGINS.
    # Có body thì bắt buộc Content-Type: application/json.

    async def dispatch(self, request: Request, call_next):
        if request.method in _UNSAFE_METHODS and "session_id" in request.cookies:
            if not _origin_allowed(request):
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "forbidden",
                        "error_description": "Origin not allowed",
                    },
                )

            content_length = request.headers.get("content-length")
            has_body = bool(content_length) and content_length != "0"
            if has_body:
                content_type = request.headers.get("content-type", "")
                if not content_type.startswith("application/json"):
                    return JSONResponse(
                        status_code=415,
                        content={
                            "error": "unsupported_media_type",
                            "error_description": "Content-Type must be application/json",
                        },
                    )

        return await call_next(request)
