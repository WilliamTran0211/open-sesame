import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger("open_sesame_logger")

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CSRFMiddleware(BaseHTTPMiddleware):
    # CSRF cho các request thay đổi trạng thái dùng cookie.
    # Bắt buộc body là JSON để ngăn tấn công từ thẻ <form> cross-site (vốn không được
    # gửi Content-Type application/json nếu không có JS chạy trên origin CORS).

    # Bỏ qua request không dùng cookie và request không body (không Content-Type/data).

    async def dispatch(self, request: Request, call_next):
        if request.method in _UNSAFE_METHODS and "session_id" in request.cookies:
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
