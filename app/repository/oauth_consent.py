from typing import List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_consent import OAuthConsent
from app.repository.base import BaseRepository


class OAuthConsentRepository(BaseRepository[OAuthConsent]):
    def __init__(self, db: AsyncSession):
        super().__init__(OAuthConsent, db)

    async def get_by_user_and_client(
        self, user_id: UUID, client_id: UUID
    ) -> Optional[OAuthConsent]:
        query = select(OAuthConsent).where(
            OAuthConsent.user_id == user_id, OAuthConsent.client_id == client_id
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def upsert(
        self, user_id: UUID, client_id: UUID, scopes: List[str]
    ) -> OAuthConsent:
        """Atomic insert for senario that two consent requests for the same (user, client) land at once."""
        stmt = (
            insert(OAuthConsent)
            .values(user_id=user_id, client_id=client_id, scopes=scopes)
            .on_conflict_do_update(
                index_elements=[OAuthConsent.user_id, OAuthConsent.client_id],
                set_={"scopes": scopes},
            )
            .returning(OAuthConsent)
        )
        result = await self.db.execute(stmt)
        await self.db.flush()
        return result.scalar_one()
