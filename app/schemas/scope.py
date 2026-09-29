from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CreateScopeSchema(BaseModel):
    name: str = Field(..., max_length=100, description="Scope identifier, e.g. 'profile'")
    description: str = Field(..., description="Shown to users when a client requests this scope")


class UpdateScopeSchema(BaseModel):
    description: Optional[str] = None
    is_active: Optional[bool] = None


class ScopeResponseSchema(BaseModel):
    name: str
    description: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
