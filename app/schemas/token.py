from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, Field


class AuthorizeQueryParams(BaseModel):
    response_type: Literal["code"]
    client_id: str
    redirect_uri: str
    scope: str = ""
    state: str = Field(
        ...,
        description=(
            "Required here (stricter than RFC 6749's RECOMMENDED) — "
            "prevents login CSRF; server always echoes it back on redirect."
        ),
    )
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[Literal["S256"]] = None


class RefreshTokenRequest(BaseModel):
    grant_type: Literal["refresh_token"]
    refresh_token: str
    client_id: str
    client_secret: Optional[str] = None


class AuthorizationCodeGrantRequest(BaseModel):
    grant_type: Literal["authorization_code"]
    code: str
    redirect_uri: str
    client_id: str
    client_secret: Optional[str] = None
    code_verifier: Optional[str] = None


TokenGrantRequest = Annotated[
    Union[RefreshTokenRequest, AuthorizationCodeGrantRequest],
    Field(discriminator="grant_type"),
]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str


class RevokeTokenRequest(BaseModel):
    token: str
    client_id: str
    client_secret: Optional[str] = None
