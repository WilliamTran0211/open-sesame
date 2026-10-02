from typing import List, Literal, Optional

from pydantic import BaseModel, Field

SupportedMfaMethod = Literal["totp", "email"]


class MfaSetupRequestSchema(BaseModel):
    method: SupportedMfaMethod = Field(..., description="'totp' or 'email'")


class MfaSetupResponseSchema(BaseModel):
    method: SupportedMfaMethod
    # secret: Base32 TOTP secret - only for totp
    secret: Optional[str] = Field(default=None)
    # provisioning_uri: otpauth:// URI - only for totp, render as a QR code in client
    provisioning_uri: Optional[str] = Field(default=None)


class MfaCodeSchema(BaseModel):
    code: str = Field(
        ..., description="6-digit code (authenticator app or email) or a recovery code"
    )


class MfaConfirmResponseSchema(BaseModel):
    recovery_codes: List[str]


class MfaChallengeResponseSchema(BaseModel):
    mfa_required: bool = True
    challenge_id: str


class MfaVerifySchema(BaseModel):
    challenge_id: str
    code: str
