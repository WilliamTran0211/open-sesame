import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.exception import InvalidGrantError
from app.services.access_token import TokenService

logger = logging.getLogger("open_sesame_logger")


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, token_service: TokenService):
        super().__init__(app)
        self.token_service = token_service

    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()
            try:
                payload = self.token_service.decode_access_token(token)
                request.state.token_payload = payload
            except InvalidGrantError:
                request.state.token_payload = None
        else:
            request.state.token_payload = None

        return await call_next(request)
