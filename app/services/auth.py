from uuid import UUID

from app.core.exception import InvalidGrantError
from app.core.security import TokenHelper
from app.models.user import User
from app.models.user_session import UserSession
from app.services.access_token import TokenService
from app.services.refresh_token import RefreshTokenServices
from app.services.user import UserService
from app.services.user_session import UserSessionService


class AuthService:
    def __init__(
        self,
        user_services: UserService,
        session_services: UserSessionService,
        token_services: RefreshTokenServices,
        access_token_service: TokenService,
    ):
        self.user_services = user_services
        self.session_services = session_services
        self.token_services = token_services
        self.access_token_service = access_token_service

    async def login(
        self, email: str, password: str, ip_address: str, user_agent: str
    ) -> tuple[User, UserSession]:
        user = await self.user_services.authenticate(email, password)
        session = await self.session_services.create_session(
            user.id, ip_address, user_agent
        )
        return user, session

    async def logout(self, session_id: str) -> None:
        await self.session_services.terminate_session(session_id)

    async def refresh_token(
        self, raw_token: str, client_id: UUID
    ) -> tuple[str, str, int]:
        token_hash = TokenHelper.hash(raw_token)
        old_token = await self.token_services.repository.get_by_hash(token_hash)

        if not old_token or old_token.client_id != client_id:
            raise InvalidGrantError("Invalid refresh token")

        raw_refresh, new_token = await self.token_services.rotate_token(
            old_token, client_id
        )
        access_token = self.access_token_service.issue_access_token(
            new_token.user_id, client_id
        )

        return access_token, raw_refresh, self.access_token_service.access_token_expire

    async def revoke_token(self, raw_token: str) -> None:
        token_hash = TokenHelper.hash(raw_token)
        token = await self.token_services.repository.get_by_hash(token_hash)

        # Per RFC 7009: succeed silently even if the token is unknown/already revoked.
        if token and not token.is_revoked:
            await self.token_services.revoke_chain(token.family_id)

    def authorize(self, token: str):
        pass

    def client_credentials(self):
        pass
