from fastapi import APIRouter

from app.api.deps import (
    CurrentUserDep,
    UserServicesDep,
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
async def reset_password():
    return {"message": "reset password"}


@router.post("/verify")
async def verify_email():
    return {"message": "verify email"}


@router.get("/list", response_model=list[UserResponseSchema])
async def get_user_list(user_services: UserServicesDep):
    list_users = await user_services.get_multi()
    return list_users
