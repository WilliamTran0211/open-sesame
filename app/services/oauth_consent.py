from typing import List
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_consent import OAuthConsent
from app.repository.oauth_consent import OAuthConsentRepository
from app.services.refresh_token import RefreshTokenServices


class OAuthConsentService:
    def __init__(self, db: AsyncSession, refresh_token_services: RefreshTokenServices):
        self.repository = OAuthConsentRepository(db)
        self.refresh_token_services = refresh_token_services

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

    async def list_user_consents(self, user_id: UUID) -> List[OAuthConsent]:
        return await self.repository.list_by_user(user_id)

    async def revoke_consent(self, user_id: UUID, client_id: UUID) -> bool:
        # Xóa record và hủy mọi refresh token client đang giữ cho user này,
        # đảm bảo app không thể tự động gọi thay mặt user sau khi bị thu hồi quyền.
        consent = await self.repository.get_by_user_and_client(user_id, client_id)
        if not consent:
            return False
        await self.repository.delete(consent.id)
        await self.refresh_token_services.revoke_by_user_and_client(user_id, client_id)
        return True
