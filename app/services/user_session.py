import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.common.error_message import ErrorMessage
from app.core.config import get_settings
from app.core.exception import NotFoundError
from app.core.redis import RedisClient
from app.models.user import User
from app.models.user_session import UserSession
from app.repository.user import UserRepository
from app.repository.user_session import UserSessionRepository


class UserSessionService:
    def __init__(self, db: AsyncSession, redis_client: RedisClient):
        self.session_repo = UserSessionRepository(db)
        self.user_repo = UserRepository(db)
        self.redis_client = redis_client

    async def create_session(
        self, user_id: str, ip_address: str, user_agent: str
    ) -> UserSession:
        user = await self.user_repo.get(user_id)

        if not user:
            raise NotFoundError(ErrorMessage.NOT_FOUND)

        data = {
            "session_id": str(uuid.uuid4()),
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "expires_at": datetime.now(timezone.utc)
            + timedelta(days=get_settings().SESSION_EXPIRE_DAYS),
        }

        new_session = await self.session_repo.create(**data)

        key = f"session:{new_session.session_id}"
        await self.redis_client.setex(
            key, get_settings().SESSION_EXPIRE_DAYS, str(user.id)
        )

        return new_session

    async def get_user_session(self, session_id: str) -> User:
        key = f"session:{session_id}"
        user_id_in_session = await self.redis_client.get(key)

        if not user_id_in_session:
            raise NotFoundError(ErrorMessage.NOT_FOUND)

        user = await self.user_repo.get(user_id_in_session)

        if not user:
            raise NotFoundError(ErrorMessage.NOT_FOUND)

        return user

    async def list_active_sessions(self, user_id: str) -> list[UserSession]:
        return await self.session_repo.get_active_by_user(user_id)

    async def terminate_session(self, session_id: str) -> None:
        session = await self.session_repo.get_by_id(session_id)
        if not session:
            raise NotFoundError(ErrorMessage.NOT_FOUND)

        key = f"session:{session.session_id}"
        await self.redis_client.delete(key)

        await self.session_repo.terminated(session.session_id)

    async def terminate_all_session(self, user_id: str) -> None:
        sessions = await self.session_repo.get_active_by_user(user_id)

        for session in sessions:
            key = f"session:{session.session_id}"
            await self.redis_client.delete(key)

        await self.session_repo.terminate_all_by_user(user_id)
