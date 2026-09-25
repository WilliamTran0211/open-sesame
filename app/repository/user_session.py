from datetime import datetime, timezone
from typing import List

from sqlalchemy import Update, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user_session import UserSession
from app.repository.base import BaseRepository


class UserSessionRepository(BaseRepository[UserSession]):
    def __init__(self, db: AsyncSession):
        self.db = db
        self.model = UserSession

    async def get_by_id(self, session_id: str) -> UserSession:
        q = select(self.model).where(self.model.session_id == session_id)
        result = await self.db.execute(q)
        return result.scalar_one_or_none()

    async def get_active_by_user(self, user_id: str) -> List[UserSession]:
        query = select(self.model).where(
            self.model.user_id == user_id, self.model.terminated_at.is_(None)
        )

        result = await self.db.execute(query)
        return result.scalars().all()

    async def terminated(self, session_id: str) -> None:
        await self.update(session_id, terminated_at=datetime.now(timezone.utc))

    async def terminate_all_by_user(self, user_id: str) -> int:
        current_time = datetime.now(timezone.utc)

        q = (
            Update(self.model)
            .where(
                self.model.user_id == user_id,
                self.model.terminated_at.is_(None),
            )
            .values(terminated_at=current_time)
        )

        result = await self.db.execute(q)
        await self.db.flush()
        return result.rowcount
