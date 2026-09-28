from typing import Any, Dict, Generic, List, Optional, Type, TypeVar
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.error_message import ErrorMessage
from app.core.exception import ConflictError
from app.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], db: AsyncSession):
        self.model = model
        self.db = db

    async def get(self, id: str) -> Optional[ModelType]:
        result = await self.db.execute(select(self.model).filter(self.model.id == id))
        return result.scalar_one_or_none()

    async def get_all(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None,
    ) -> List[ModelType]:
        query = select(self.model)

        if filters:
            for field, value in filters.items():
                if hasattr(self.model, field):
                    query = query.where(getattr(self.model, field) == value)

        if order_by and hasattr(self.model, order_by):
            query = query.order_by(getattr(self.model, order_by))

        query = query.offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def create(self, **kwargs) -> ModelType:
        instance = self.model(**kwargs)
        self.db.add(instance)
        try:
            await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            raise ConflictError(ErrorMessage.CONFLICT)
        return instance

    async def update(self, id: UUID, **kwargs) -> Optional[ModelType]:
        """Update record."""
        query = (
            update(self.model)
            .where(self.model.id == id)
            .values(**kwargs)
            .returning(self.model)
        )
        try:
            result = await self.db.execute(query)
            await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            raise ConflictError(ErrorMessage.CONFLICT)
        return result.scalar_one_or_none()

    async def delete(self, id: UUID) -> bool:
        query = delete(self.model).where(self.model.id == id)
        result = await self.db.execute(query)
        await self.db.flush()
        return result.rowcount > 0
