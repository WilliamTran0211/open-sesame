import secrets
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.common.enum import ClientType
from app.common.error_message import ErrorMessage
from app.core.exception import InvalidRequestError, NotFoundError
from app.core.security import SecurityHelper
from app.models.client import OAuthClient
from app.repository.client import OAuthClientRepository
from app.repository.user import UserRepository
from app.services.refresh_token import RefreshTokenServices


class OAuthClientService:
    def __init__(self, db: AsyncSession, refresh_token_services: RefreshTokenServices):
        self.repository = OAuthClientRepository(db)
        self.user_repository = UserRepository(db)
        self.refresh_token_services = refresh_token_services

    async def create_client(
        self,
        name: str,
        redirect_uris: list[str],
        grant_types: list[str],
        client_type: ClientType = ClientType.CONFIDENTIAL,
        owner_id: Optional[str] = None,
        require_pkce: bool = True,
        access_token_ttl: Optional[int] = None,
        refresh_token_ttl: Optional[int] = None,
    ) -> OAuthClient:
        client_id = secrets.token_urlsafe(32)
        client_secret = (
            secrets.token_urlsafe(48)
            if client_type == ClientType.CONFIDENTIAL
            else None
        )
        client_secret_hash = (
            SecurityHelper.hash_sha256(client_secret) if client_secret else None
        )

        if owner_id:
            owner = await self.user_repository.get(owner_id)
            if not owner:
                raise NotFoundError(ErrorMessage.NOT_FOUND)

        client = await self.repository.create(
            client_id=client_id,
            client_secret_hash=client_secret_hash,
            client_type=client_type,
            name=name,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            require_pkce=require_pkce,
            access_token_ttl=access_token_ttl,
            refresh_token_ttl=refresh_token_ttl,
            owner_id=owner_id,
            is_active=True,
        )

        client.client_secret = client_secret
        return client

    async def get_client_by_id(self, client_id: str) -> OAuthClient:
        client = await self.repository.get_by_client_id(client_id)
        if not client:
            raise NotFoundError(ErrorMessage.NOT_FOUND)
        return client

    async def validate_client_secret(
        self, client: OAuthClient, client_secret: str
    ) -> bool:
        if not client.client_secret_hash:
            return False
        return SecurityHelper.secure_compare(
            SecurityHelper.hash_sha256(client_secret), client.client_secret_hash
        )

    async def validate_redirect_uri(
        self, client: OAuthClient, redirect_uri: str
    ) -> bool:
        return redirect_uri in client.redirect_uris

    async def validate_grant_type(self, client: OAuthClient, grant_type: str) -> bool:
        return grant_type in client.grant_types

    async def update_client(
        self,
        client_id: str,
        data: dict,
    ) -> OAuthClient:
        client = await self.get_client_by_id(client_id)
        if "client_secret" in data and data["client_secret"] is not None:
            data["client_secret_hash"] = SecurityHelper.hash_sha256(
                data.pop("client_secret")
            )
        return await self.repository.update(client.id, **data)

    async def deactivate_client(self, client_id: str) -> OAuthClient:
        client = await self.get_client_by_id(client_id)
        await self.refresh_token_services.revoke_by_client(client.id)
        return await self.update_client(client.client_id, {"is_active": False})

    async def list_client_by_owner(self, owner_id: str) -> List[OAuthClient]:
        return await self.repository.get_by_owner(owner_id)

    async def list_active_clients(self) -> List[OAuthClient]:
        return await self.repository.get_active_clients()

    async def rotate_secret(self, client_id: str) -> str:
        client = await self.get_client_by_id(client_id)
        if not client.client_type == ClientType.CONFIDENTIAL:
            raise InvalidRequestError(ErrorMessage.INVALID_REQUEST)
        new_secret = secrets.token_urlsafe(48)
        client_secret_hash = SecurityHelper.hash_sha256(new_secret)

        await self.repository.update(client.id, client_secret_hash=client_secret_hash)

        return new_secret

    async def activate_client(self, client_id: str) -> OAuthClient:
        client = await self.get_client_by_id(client_id)
        return await self.update_client(client.client_id, {"is_active": True})
