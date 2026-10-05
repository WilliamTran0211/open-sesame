from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Cookie, Query, Request
from fastapi.responses import RedirectResponse

from app.api.deps import (
    AuthServicesDep,
    OAuthClientServiceDep,
    OAuthConsentServicesDep,
    RequireSessionDep,
    UserSessionServicesDep,
)
from app.common.enum import ClientType
from app.common.error_message import ErrorMessage
from app.core.config import get_settings
from app.core.exception import (
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    NotFoundError,
    UnauthorizedClientError,
)
from app.core.rate_limit import rate_limit
from app.schemas.token import (
    AuthorizeQueryParams,
    ConsentRequest,
    ConsentResponse,
    RevokeTokenRequest,
    TokenGrantRequest,
    TokenResponse,
)

router = APIRouter()


def _append_query(url: str, params: dict) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(params)}"


@router.get("/")
def read_root():
    return {"message": "Open Sesame, OAuth service!"}


@router.get("/authorize")
async def authorize_user(
    params: Annotated[AuthorizeQueryParams, Query()],
    request: Request,
    client_service: OAuthClientServiceDep,
    auth_service: AuthServicesDep,
    user_session_services: UserSessionServicesDep,
    consent_service: OAuthConsentServicesDep,
    session_id: Annotated[str | None, Cookie()] = None,
):
    client = await client_service.get_client_by_id(params.client_id)

    # redirect_uri đã được xác thực trong validate_authorize_request
    # có thể báo lỗi scope bằng cách chuyển hướng về client thay vì báo lỗi trực tiếp.
    try:
        granted_scope = await client_service.validate_authorize_request(
            client, params.redirect_uri, params.scope
        )
    except InvalidScopeError:
        error_url = _append_query(
            params.redirect_uri, {"error": "invalid_scope", "state": params.state}
        )
        return RedirectResponse(error_url)

    user = None
    if session_id:
        try:
            user = await user_session_services.get_user_session(session_id)
        except NotFoundError:
            user = None

    if not user:
        login_url = _append_query(
            get_settings().FRONTEND_LOGIN_URL, {"redirect_uri": str(request.url)}
        )
        return RedirectResponse(login_url)

    # Chưa allow thì không tự động cấp authorization code.
    # URl tạo sẵn đến endpoint này phải đưa người dùng đến màn hình allow.
    if not await consent_service.has_consent(user.id, client.id, granted_scope):
        consent_url = _append_query(
            get_settings().FRONTEND_CONSENT_URL, dict(request.query_params)
        )
        return RedirectResponse(consent_url)

    try:
        code = await auth_service.authorize(
            client=client,
            user_id=user.id,
            redirect_uri=params.redirect_uri,
            scope=granted_scope,
            code_challenge=params.code_challenge,
        )
    except InvalidRequestError:
        error_url = _append_query(
            params.redirect_uri, {"error": "invalid_request", "state": params.state}
        )
        return RedirectResponse(error_url)

    success_url = _append_query(
        params.redirect_uri, {"code": code, "state": params.state}
    )
    return RedirectResponse(success_url)


@router.post("/consent", response_model=ConsentResponse)
async def consent(
    body: ConsentRequest,
    current_user: RequireSessionDep,
    client_service: OAuthClientServiceDep,
    auth_service: AuthServicesDep,
    consent_service: OAuthConsentServicesDep,
):
    client = await client_service.get_client_by_id(body.client_id)
    granted_scope = await client_service.validate_authorize_request(
        client, body.redirect_uri, body.scope
    )

    await consent_service.grant_consent(current_user.id, client.id, granted_scope)

    code = await auth_service.authorize(
        client=client,
        user_id=current_user.id,
        redirect_uri=body.redirect_uri,
        scope=granted_scope,
        code_challenge=body.code_challenge,
    )

    redirect_to = _append_query(body.redirect_uri, {"code": code, "state": body.state})
    return ConsentResponse(redirect_to=redirect_to)


@router.post(
    "/token",
    response_model=TokenResponse,
    dependencies=[rate_limit("token", identifier_field="client_id")],
)
async def token_exchange(
    body: TokenGrantRequest,
    auth_service: AuthServicesDep,
    client_service: OAuthClientServiceDep,
):
    client = await client_service.get_client_by_id(body.client_id)

    if not client.is_active:
        raise InvalidClientError(ErrorMessage.INVALID_CLIENT)
    if not await client_service.validate_grant_type(client, body.grant_type):
        raise UnauthorizedClientError(ErrorMessage.UNAUTHORIZED_CLIENT)
    if client.client_type == ClientType.CONFIDENTIAL:
        if not body.client_secret or not await client_service.validate_client_secret(
            client, body.client_secret
        ):
            raise InvalidClientError(ErrorMessage.INVALID_CLIENT)

    if body.grant_type == "refresh_token":
        access_token, raw_refresh, expires_in = await auth_service.refresh_token(
            body.refresh_token, client.id
        )
    else:
        (
            access_token,
            raw_refresh,
            expires_in,
        ) = await auth_service.exchange_authorization_code(
            client, body.code, body.redirect_uri, body.code_verifier
        )

    return TokenResponse(
        access_token=access_token,
        expires_in=expires_in,
        refresh_token=raw_refresh,
    )


@router.post(
    "/token/revoke",
    dependencies=[rate_limit("token-revoke", identifier_field="client_id")],
)
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
