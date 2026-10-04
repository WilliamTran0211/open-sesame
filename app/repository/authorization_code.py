from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization_code import AuthorizationCode
from app.repository.base import BaseRepository


class AuthorizationCodeRepository(BaseRepository[AuthorizationCode]):
    def __init__(self, db: AsyncSession):
        super().__init__(AuthorizationCode, db)

    async def get_by_code(self, auth_code: str) -> Optional[AuthorizationCode]:
        query = select(AuthorizationCode).where(AuthorizationCode.code == auth_code)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def mark_used(self, code_id: UUID) -> bool:
        stmt = (
            update(AuthorizationCode)
            .where(
                AuthorizationCode.id == code_id,
                AuthorizationCode.used_at.is_(None),
            )
            .values(used_at=datetime.now(timezone.utc))
        )
        result = await self.db.execute(stmt)
        await self.db.flush()
        return result.rowcount > 0

    async def delete_expired(self) -> int:
        stmt = delete(AuthorizationCode).where(
            AuthorizationCode.expires_at < datetime.now(timezone.utc)
        )
        result = await self.db.execute(stmt)
        await self.db.flush()
        return result.rowcount
