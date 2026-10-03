from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_consent import OAuthConsent
from app.repository.oauth_consent import OAuthConsentRepository


class OAuthConsentService:
    def __init__(self, db: AsyncSession):
        self.repository = OAuthConsentRepository(db)

    async def has_consent(self, user_id: UUID, client_id: UUID, granted_scope: str) -> bool:
        consent = await self.repository.get_by_user_and_client(user_id, client_id)
        if not consent:
            return False

        requested = set(granted_scope.split())
        return requested.issubset(set(consent.scopes))

    async def grant_consent(
        self, user_id: UUID, client_id: UUID, granted_scope: str
    ) -> OAuthConsent:
        existing = await self.repository.get_by_user_and_client(user_id, client_id)
        requested = set(granted_scope.split())
        union_scopes = requested | set(existing.scopes) if existing else requested
        return await self.repository.upsert(user_id, client_id, sorted(union_scopes))
