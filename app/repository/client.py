from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.client import OAuthClient
from app.repository.base import BaseRepository


class OAuthClientRepository(BaseRepository[OAuthClient]):
    def __init__(self, db: AsyncSession):
        super().__init__(OAuthClient, db)

    async def get_by_client_id(self, client_id: str) -> Optional[OAuthClient]:
        query = select(OAuthClient).where(OAuthClient.client_id == client_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_by_owner(self, owner_id: str) -> List[OAuthClient]:
        return await self.get_all(filters={"owner_id": owner_id})

    async def get_active_clients(self) -> List[OAuthClient]:
        return await self.get_all(filters={"is_active": True})
