from datetime import datetime, timedelta, timezone
from typing import Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exception import InvalidGrantError
from app.core.security import TokenHelper
from app.models.refresh_token import RefreshToken
from app.repository.refresh_token import RefreshTokenRepository


class RefreshTokenServices:
    def __init__(self, db: AsyncSession):
        self.repository = RefreshTokenRepository(db)
        self.token_helper = TokenHelper

    async def create_token(
        self, user_id: UUID, client_id: UUID, ttl_days: int = 7
    ) -> Tuple[str, RefreshToken]:
        raw_token = self.token_helper.generate()
        token_hash = self.token_helper.hash(raw_token)
        exp_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)

        refresh_token = await self.repository.create(
            token_hash=token_hash,
            user_id=user_id,
            client_id=client_id,
            expires_at=exp_at,
        )

        return raw_token, refresh_token

    async def rotate_token(
        self, old_token: RefreshToken, client_id: UUID
    ) -> Tuple[str, RefreshToken]:
        if old_token.is_expired:
            raise InvalidGrantError("Refresh token expired")

        revoked_now = await self.repository.revoke_if_active(old_token.id)
        if not revoked_now:
            await self.revoke_chain(old_token.family_id)
            raise InvalidGrantError("Refresh token reuse detected")

        raw_token = self.token_helper.generate()
        token_hash = self.token_helper.hash(raw_token)
        exp_at = datetime.now(timezone.utc) + timedelta(days=7)

        new_token = await self.repository.create(
            token_hash=token_hash,
            user_id=old_token.user_id,
            client_id=client_id,
            expires_at=exp_at,
            family_id=old_token.family_id,
            parent_id=old_token.id,
        )

        return raw_token, new_token

    async def revoke_chain(self, family_id: UUID) -> None:
        await self.repository.revoke_by_family(family_id)

    async def revoke_by_client(self, client_id: UUID) -> None:
        await self.repository.revoke_by_client(client_id)
