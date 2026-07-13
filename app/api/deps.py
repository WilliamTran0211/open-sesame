import uuid
from typing import Annotated

from fastapi import Cookie, Depends, Request

from app.common.error_message import ErrorMessage
from app.core.deps import RedisDep
from app.core.exception import UnauthorizedError
from app.db.deps import DBDep
from app.models.user import User
from app.services.auth import AuthService
from app.services.otp import OTPService
from app.services.user import UserService
from app.services.user_session import UserSessionService


def get_otp_service(redis_client: RedisDep) -> OTPService:
    return OTPService(redis_client)


def get_user_services(
    db: DBDep,
    otp_service: OTPService = Depends(get_otp_service),
) -> UserService:
    return UserService(db, otp_service)


def get_auth_services(
    db: DBDep,
    redis_client: RedisDep,
) -> AuthService:
    user_services = UserService(db)
    session_services = UserSessionService(db, redis_client)
    return AuthService(user_services, session_services)


def get_user_session_services(
    db: DBDep,
    redis_client: RedisDep,
) -> UserSessionService:
    return UserSessionService(db, redis_client)


async def get_current_user(
    request: Request,
    session_id: Annotated[str | None, Cookie()] = None,
    user_service: UserService = Depends(get_user_services),
    user_session_services: UserSessionService = Depends(get_user_session_services),
) -> User:
    payload = request.state.token_payload
    if payload:
        return await user_service.get_active_user(uuid.UUID(payload.sub))

    if session_id:
        return await user_session_services.get_user_session(session_id)

    raise UnauthorizedError(ErrorMessage.UNAUTHORIZED)


async def require_token(
    request: Request,
    user_service: UserService = Depends(get_user_services),
) -> User:
    payload = request.state.token_payload
    if not payload:
        raise UnauthorizedError(ErrorMessage.UNAUTHORIZED)
    return await user_service.get_active_user(uuid.UUID(payload.sub))


async def require_session(
    session_id: Annotated[str | None, Cookie()] = None,
    user_session_services: UserSessionService = Depends(get_user_session_services),
) -> User:
    if not session_id:
        raise UnauthorizedError(ErrorMessage.UNAUTHORIZED)
    return await user_session_services.get_user_session(session_id)


OtpServicesDep = Annotated[OTPService, Depends(get_otp_service)]
UserServicesDep = Annotated[UserService, Depends(get_user_services)]

AuthServicesDep = Annotated[AuthService, Depends(get_auth_services)]
UserSessionServicesDep = Annotated[
    UserSessionService, Depends(get_user_session_services)
]

CurrentUserDep = Annotated[User, Depends(get_current_user)]
RequireTokenDep = Annotated[User, Depends(require_token)]
RequireSessionDep = Annotated[User, Depends(require_session)]
