import logging
from typing import Annotated

from fastapi import APIRouter, Cookie, Request, Response

from app.api.deps import AuthServicesDep, OAuthClientServiceDep
from app.common.enum import ClientType
from app.common.error_message import ErrorMessage
from app.core.config import get_settings
from app.core.exception import (
    ForbiddenError,
    InvalidClientError,
    UnauthorizedClientError,
)
from app.schemas.token import RefreshTokenRequest, RevokeTokenRequest, TokenResponse
from app.schemas.user import UserLogin, UserResponseSchema

router = APIRouter()

logger = logging.getLogger("open_sesame_logger")


@router.get("/")
def read_root():
    logger.debug("Root endpoint accessed")
    return {"message": "Open Sesame, Authentication!"}


@router.post("/login")
async def login(
    body: UserLogin,
    request: Request,
    response: Response,
    auth_service: AuthServicesDep,
):
    data = {
        "email": body.email,
        "password": body.password,
        "ip_address": request.client.host,
        "user_agent": request.headers.get("user-agent"),
    }

    user, session = await auth_service.login(**data)

    response.set_cookie(
        key="session_id",
        value=session.session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=get_settings().session_max_age_seconds,
    )

    return UserResponseSchema.model_validate(user)


@router.post("/logout")
async def logout(
    session_id: Annotated[str | None, Cookie()],
    auth_service: AuthServicesDep,
):
    if not session_id:
        raise ForbiddenError(ErrorMessage.ACCESS_DENIED)

    await auth_service.logout(session_id)
    return {"message": "success"}


@router.get("/authorize")
async def authorize_user():
    return


@router.post("/token", response_model=TokenResponse)
async def token_exchange(
    body: RefreshTokenRequest,
    auth_service: AuthServicesDep,
    client_service: OAuthClientServiceDep,
):
    client = await client_service.get_client_by_id(body.client_id)

    if not client.is_active:
        raise InvalidClientError(ErrorMessage.INVALID_CLIENT)
    if not await client_service.validate_grant_type(client, "refresh_token"):
        raise UnauthorizedClientError(ErrorMessage.UNAUTHORIZED_CLIENT)
    if client.client_type == ClientType.CONFIDENTIAL:
        if not body.client_secret or not await client_service.validate_client_secret(
            client, body.client_secret
        ):
            raise InvalidClientError(ErrorMessage.INVALID_CLIENT)

    access_token, raw_refresh, expires_in = await auth_service.refresh_token(
        body.refresh_token, client.id
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=raw_refresh,
    )


@router.post("/token/revoke")
async def revoke_token(
    body: RevokeTokenRequest,
    auth_service: AuthServicesDep,
    client_service: OAuthClientServiceDep,
):
    client = await client_service.get_client_by_id(body.client_id)

    if client.client_type == ClientType.CONFIDENTIAL:
        if not body.client_secret or not await client_service.validate_client_secret(
            client, body.client_secret
        ):
            raise InvalidClientError(ErrorMessage.INVALID_CLIENT)

    await auth_service.revoke_token(body.token)
    return {"message": "success"}
