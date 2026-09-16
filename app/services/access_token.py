from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from typing import Optional
from uuid import UUID

from app.core.config import get_settings
from app.core.deps import get_jwt_helper
from app.core.exception import InvalidGrantError
from app.core.security import JWTHelper


@dataclass
class AccessTokenPayload:
    sub: str
    client_id: Optional[str]
    scope: str
    exp: int


class TokenService:
    """Issues and validates short-lived JWT access tokens."""

    def __init__(self, jwt_helper: JWTHelper, access_token_expire: int = 900):
        self.jwt_helper = jwt_helper
        self.access_token_expire = access_token_expire

    def issue_access_token(
        self, user_id: UUID, client_id: Optional[UUID] = None, scope: str = ""
    ) -> str:
        return self.jwt_helper.create(
            subject=str(user_id),
            expires_delta=timedelta(seconds=self.access_token_expire),
            token_type="access",
            client_id=str(client_id) if client_id else None,
            scope=scope,
        )

    def decode_access_token(self, token: str) -> AccessTokenPayload:
        payload = self.jwt_helper.decode(token)
        if not payload or payload.get("type") != "access":
            raise InvalidGrantError("Invalid or expired access token")

        return AccessTokenPayload(
            sub=payload["sub"],
            client_id=payload.get("client_id"),
            scope=payload.get("scope", ""),
            exp=payload["exp"],
        )


@lru_cache()
def get_token_service() -> TokenService:
    settings = get_settings()
    return TokenService(
        jwt_helper=get_jwt_helper(),
        access_token_expire=settings.ACCESS_TOKEN_EXPIRE,
    )
