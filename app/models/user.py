from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Index, String, func, select
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.authorization_code import AuthorizationCode
from app.models.base import Base, TimestampMixin, UUIDMixin
from app.models.client import OAuthClient
from app.models.refresh_token import RefreshToken
from app.models.user_session import UserSession


class User(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Account status
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Platform-level admin. NOT an OAuth scope.",
    )

    owned_clients: Mapped[List["OAuthClient"]] = relationship(
        "OAuthClient", back_populates="owner", cascade="all, delete-orphan"
    )
    authorization_codes: Mapped[List["AuthorizationCode"]] = relationship(
        "AuthorizationCode", back_populates="user", cascade="all, delete-orphan"
    )
    refresh_tokens: Mapped[List["RefreshToken"]] = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[List["UserSession"]] = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_users_email_lower", func.lower(email)),  # case-insensitive lookup
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r}>"
