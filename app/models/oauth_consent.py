import uuid
from typing import TYPE_CHECKING, List

from sqlalchemy import ARRAY, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.client import OAuthClient
    from app.models.user import User


class OAuthConsent(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "oauth_consents"

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
    scopes: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False, default=list)

    user: Mapped["User"] = relationship("User", back_populates="consents")
    client: Mapped["OAuthClient"] = relationship("OAuthClient", back_populates="consents")

    __table_args__ = (
        UniqueConstraint("user_id", "client_id", name="uq_oauth_consents_user_client"),
    )

    def __repr__(self) -> str:
        return f"<OAuthConsent user_id={self.user_id} client_id={self.client_id}>"
