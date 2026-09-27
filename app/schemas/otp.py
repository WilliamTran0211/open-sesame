from pydantic import BaseModel, EmailStr, Field


class VerifyEmailSchema(BaseModel):
    email: EmailStr = Field(..., description="Email the code was sent to")
    otp: str = Field(..., pattern=r"^\d{6}$", description="6-digit verification code")


class ResendVerificationSchema(BaseModel):
    email: EmailStr = Field(..., description="Email to resend the code to")
