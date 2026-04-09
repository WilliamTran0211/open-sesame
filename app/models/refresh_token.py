import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.client import OAuthClient
    from app.models.user import User


class RefreshToken(UUIDMixin, TimestampMixin, Base):
    """
    Long-lived credential for obtaining new access tokens.

    Security model — token rotation with family revocation:
        - Chỉ lưu SHA-256 hash, không bao giờ lưu raw token.
        - Mỗi lần dùng → issue token mới, token cũ bị revoke (rotated).
        - family_id liên kết tất cả các token nào cùng một authorization.
        - Nếu token đã rotate mà được dùng lại (stolen)
            → revoke toàn bộ family.
    """

    __tablename__ = "refresh_tokens"

    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
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

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, default=uuid.uuid4, index=True
    )
    parent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )

    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")
    client: Mapped["OAuthClient"] = relationship(
        "OAuthClient", back_populates="refresh_tokens"
    )
    children: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken",
        foreign_keys=[parent_id],
        backref="parent",
    )

    __table_args__ = (
        Index("ix_refresh_tokens_family_id", "family_id"),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
        Index("ix_refresh_tokens_user_client", "user_id", "client_id"),
    )

    @property
    def is_expired(self) -> bool:
        from datetime import datetime as dt
        from datetime import timezone

        return dt.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired and self.parent_id is None

    def __repr__(self) -> str:
        return (
            f"<RefreshToken id={self.id} user_id={self.user_id} "
            f"revoked={self.is_revoked} expired={self.is_expired}>"
        )
