from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.refresh_token import RefreshToken
from app.repository.base import BaseRepository


class RefreshTokenRepository(BaseRepository[RefreshToken]):
    def __init__(self, db: AsyncSession):
        super().__init__(RefreshToken, db)

    async def get_by_hash(self, token_hash: str) -> Optional[RefreshToken]:
        query = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def revoke_by_client(self, client_id: UUID) -> None:
        """
        This using for cases that client was deactivated. 
        Need to revoke all the token are current available for that client.
        """
        stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.client_id == client_id,
                RefreshToken.is_revoked.is_(False),
            )
            .values(is_revoked=True, revoked_at=datetime.now(timezone.utc))
        )
        await self.db.execute(stmt)
        await self.db.flush()

    async def revoke_by_family(self, family_id: UUID) -> None:
        stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.family_id == family_id,
                RefreshToken.is_revoked.is_(False),
            )
            .values(is_revoked=True, revoked_at=datetime.now(timezone.utc))
        )
        await self.db.execute(stmt)
        await self.db.flush()

    async def revoke_if_active(self, token_id: UUID) -> bool:
        """
        Revoke a token only if it isn't already revoked.
        Returns True if this call revoked it, False if it was already revoked.
        """
        stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.id == token_id,
                RefreshToken.is_revoked.is_(False),
            )
            .values(is_revoked=True, revoked_at=datetime.now(timezone.utc))
        )
        result = await self.db.execute(stmt)
        await self.db.flush()
        return result.rowcount > 0
