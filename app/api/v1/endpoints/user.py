from fastapi import APIRouter

from app.api.deps import (
    CurrentUserDep,
    RequireSuperuserDep,
    UserServicesDep,
)
from app.common.enum import MFAMethod
from app.core.rate_limit import rate_limit
from app.schemas.mfa import (
    MfaCodeSchema,
    MfaConfirmResponseSchema,
    MfaSetupRequestSchema,
    MfaSetupResponseSchema,
)
from app.schemas.otp import (
    ConfirmPasswordResetSchema,
    RequestPasswordResetSchema,
    ResendVerificationSchema,
    VerifyEmailSchema,
)
from app.schemas.user import (
    ChangePasswordSchema,
    CreateUserSchema,
    UpdateUserSchema,
    UserResponseSchema,
)

router = APIRouter()


@router.get("/")
def read_root():
    return {"message": "Open Sesame, User service!"}


@router.get("/me", response_model=UserResponseSchema)
async def get_me(current_user: CurrentUserDep):
    return current_user


@router.patch("/me", response_model=UserResponseSchema)
async def update_me(
    data: UpdateUserSchema,
    user_services: UserServicesDep,
    current_user: CurrentUserDep,
):
    user = await user_services.update_user(str(current_user.id), data)
    return user


@router.post("/me/change-password")
async def change_password(
    data: ChangePasswordSchema,
    user_services: UserServicesDep,
    current_user: CurrentUserDep,
):
    result = await user_services.change_password(
        user_id=current_user.id,
        current_password=data.current_password,
        new_password=data.new_password,
    )
    return result


@router.post("/me/2fa/setup", response_model=MfaSetupResponseSchema)
async def setup_mfa(
    data: MfaSetupRequestSchema,
    user_services: UserServicesDep,
    current_user: CurrentUserDep,
):
    result = await user_services.setup_mfa(str(current_user.id), MFAMethod(data.method))
    return MfaSetupResponseSchema(
        method=result.method.value,
        secret=result.secret,
        provisioning_uri=result.provisioning_uri,
    )


@router.post("/me/2fa/confirm", response_model=MfaConfirmResponseSchema)
async def confirm_mfa(
    data: MfaCodeSchema,
    user_services: UserServicesDep,
    current_user: CurrentUserDep,
):
    recovery_codes = await user_services.confirm_mfa(str(current_user.id), data.code)
    return MfaConfirmResponseSchema(recovery_codes=recovery_codes)


@router.post("/me/2fa/request-code")
async def request_mfa_code(
    user_services: UserServicesDep,
    current_user: CurrentUserDep,
):
    """Send a fresh email OTP — needed before confirm/disable when the
    method is EMAIL. No-op for TOTP."""
    await user_services.request_mfa_code(str(current_user.id))
    return {"message": "success"}


@router.post("/me/2fa/disable")
async def disable_mfa(
    data: MfaCodeSchema,
    user_services: UserServicesDep,
    current_user: CurrentUserDep,
):
    await user_services.disable_mfa(str(current_user.id), data.code)
    return {"message": "success"}


@router.post(
    "/register",
    response_model=UserResponseSchema,
    dependencies=[rate_limit("register", identifier_field="email")],
)
async def register(user_data: CreateUserSchema, user_services: UserServicesDep):
    user = await user_services.create_user(user_data)
    return user


@router.post("/reset-password")
async def reset_password(
    data: RequestPasswordResetSchema, user_services: UserServicesDep
):
    await user_services.request_password_reset(data.email)
    return {"message": "success"}


@router.post(
    "/reset-password/confirm",
    response_model=UserResponseSchema,
    dependencies=[rate_limit("reset-password", identifier_field="email")],
)
async def confirm_reset_password(
    data: ConfirmPasswordResetSchema, user_services: UserServicesDep
):
    return await user_services.confirm_password_reset(
        data.email, data.otp, data.new_password
    )


@router.post(
    "/verify",
    response_model=UserResponseSchema,
    dependencies=[rate_limit("verify-email", identifier_field="email")],
)
async def verify_email(data: VerifyEmailSchema, user_services: UserServicesDep):
    user = await user_services.verify_email(data.email, data.otp)
    return user


@router.post(
    "/verify/resend",
    dependencies=[rate_limit("verify-email", identifier_field="email")],
)
async def resend_verification(
    data: ResendVerificationSchema, user_services: UserServicesDep
):
    await user_services.resend_verification(data.email)
    return {"message": "success"}


@router.get("/list", response_model=list[UserResponseSchema])
async def get_user_list(user_services: UserServicesDep, _: RequireSuperuserDep):
    list_users = await user_services.get_multi()
    return list_users
