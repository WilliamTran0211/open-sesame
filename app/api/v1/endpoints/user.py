from fastapi import APIRouter

from app.api.deps import (
    CurrentUserDep,
    RequireSuperuserDep,
    UserServicesDep,
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


@router.post("/register", response_model=UserResponseSchema)
async def register(user_data: CreateUserSchema, user_services: UserServicesDep):
    user = await user_services.create_user(user_data)
    return user


@router.post("/reset-password")
async def reset_password(
    data: RequestPasswordResetSchema, user_services: UserServicesDep
):
    await user_services.request_password_reset(data.email)
    return {"message": "success"}


@router.post("/reset-password/confirm", response_model=UserResponseSchema)
async def confirm_reset_password(
    data: ConfirmPasswordResetSchema, user_services: UserServicesDep
):
    return await user_services.confirm_password_reset(
        data.email, data.otp, data.new_password
    )


@router.post("/verify", response_model=UserResponseSchema)
async def verify_email(data: VerifyEmailSchema, user_services: UserServicesDep):
    user = await user_services.verify_email(data.email, data.otp)
    return user


@router.post("/verify/resend")
async def resend_verification(
    data: ResendVerificationSchema, user_services: UserServicesDep
):
    await user_services.resend_verification(data.email)
    return {"message": "success"}


@router.get("/list", response_model=list[UserResponseSchema])
async def get_user_list(user_services: UserServicesDep, _: RequireSuperuserDep):
    list_users = await user_services.get_multi()
    return list_users
