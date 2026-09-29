from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scope import Scope
from app.repository.base import BaseRepository


class ScopeRepository(BaseRepository[Scope]):
    def __init__(self, db: AsyncSession):
        super().__init__(Scope, db)

    async def get_by_name(self, name: str) -> Optional[Scope]:
        query = select(Scope).where(Scope.name == name)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def list_active(self) -> List[Scope]:
        return await self.get_all(filters={"is_active": True})
