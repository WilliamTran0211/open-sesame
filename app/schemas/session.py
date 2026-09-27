from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class SessionResponseSchema(BaseModel):
    session_id: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}
