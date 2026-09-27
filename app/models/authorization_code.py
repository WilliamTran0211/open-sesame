import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.client import OAuthClient
    from app.models.user import User


class AuthorizationCode(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "authorization_codes"

    code: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("oauth_clients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    scope: Mapped[str] = mapped_column(Text, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)

    code_challenge: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    code_challenge_method: Mapped[Optional[str]] = mapped_column(
        String(50),
        default="S256",
        server_default="S256",
        nullable=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="5 min",
    )

    used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    user: Mapped["User"] = relationship("User", back_populates="authorization_codes")
    client: Mapped["OAuthClient"] = relationship(
        "OAuthClient", back_populates="authorization_codes"
    )

    __table_args__ = (
        Index("ix_auth_codes_expires_at", "expires_at"),  # for cleanup job
    )

    @property
    def is_expired(self) -> bool:
        from datetime import datetime as dt
        from datetime import timezone

        return dt.now(timezone.utc) > self.expires_at

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    def __repr__(self) -> str:
        return f"<AuthorizationCode id={self.id} client_id={self.client_id} used={self.is_used}>"
