from typing import List

from sqlalchemy.ext.asyncio import AsyncSession

from app.common.error_message import ErrorMessage
from app.core.exception import ConflictError, InvalidRequestError, NotFoundError
from app.models.scope import Scope
from app.repository.scope import ScopeRepository


class ScopeServices:
    def __init__(self, db: AsyncSession):
        self.repository = ScopeRepository(db)

    async def create_scope(self, name: str, description: str) -> Scope:
        existing = await self.repository.get_by_name(name)
        if existing:
            raise ConflictError(ErrorMessage.CONFLICT)
        return await self.repository.create(
            name=name, description=description, is_active=True
        )

    async def get_scope(self, name: str) -> Scope:
        scope = await self.repository.get_by_name(name)
        if not scope:
            raise NotFoundError(ErrorMessage.NOT_FOUND)
        return scope

    async def list_active_scopes(self) -> List[Scope]:
        return await self.repository.list_active()

    async def update_scope(self, name: str, data: dict) -> Scope:
        scope = await self.get_scope(name)
        if not data:
            return scope
        return await self.repository.update(scope.id, **data)

    async def deactivate_scope(self, name: str) -> Scope:
        return await self.update_scope(name, {"is_active": False})

    async def validate_scope_names(self, names: List[str]) -> None:
        """Reject client registration/update if it references a scope that
        doesn't exist or has been deactivated
        catches typos at write time instead of failing later."""
        if not names:
            return 
        active_names = {s.name for s in await self.list_active_scopes()}
        unknown = set(names) - active_names
        if unknown:
            raise InvalidRequestError(ErrorMessage.INVALID_SCOPE)
