import logging
from typing import Annotated

from fastapi import APIRouter, Cookie, Request, Response

from app.api.deps import AuthServicesDep
from app.common.error_message import ErrorMessage
from app.core.config import get_settings
from app.core.exception import ForbiddenError
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
