import re

from pydantic import BaseModel, EmailStr, Field, field_validator


class VerifyEmailSchema(BaseModel):
    email: EmailStr = Field(..., description="Email the code was sent to")
    otp: str = Field(..., pattern=r"^\d{6}$", description="6-digit verification code")


class ResendVerificationSchema(BaseModel):
    email: EmailStr = Field(..., description="Email to resend the code to")


class RequestPasswordResetSchema(BaseModel):
    email: EmailStr = Field(..., description="Email to send the reset code to")


class ConfirmPasswordResetSchema(BaseModel):
    email: EmailStr = Field(..., description="Email the reset code was sent to")
    otp: str = Field(..., pattern=r"^\d{6}$", description="6-digit verification code")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=100,
        description="Password must be 8-100 characters",
    )

    @field_validator("new_password")
    def validate_password_complexity(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one number")
        return v
