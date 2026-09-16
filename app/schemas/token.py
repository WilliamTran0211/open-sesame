from typing import Literal, Optional

from pydantic import BaseModel


class RefreshTokenRequest(BaseModel):
    grant_type: Literal["refresh_token"]
    refresh_token: str
    client_id: str
    client_secret: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str


class RevokeTokenRequest(BaseModel):
    token: str
    client_id: str
    client_secret: Optional[str] = None
