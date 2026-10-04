import logging

from app.core.redis import RedisClient
from app.db.session import session_manager
from app.repository.authorization_code import AuthorizationCodeRepository
from app.repository.refresh_token import RefreshTokenRepository

logger = logging.getLogger("open_sesame_logger")

LOCK_KEY = "cleanup:expired-tokens:lock"
LOCK_TTL = 60


async def cleanup_expired_tokens(redis_client: RedisClient) -> None:
    if not await redis_client.acquire_lock(LOCK_KEY, LOCK_TTL):
        return

    async with session_manager.session() as db:
        auth_code_cnt = await AuthorizationCodeRepository(db).delete_expired()
        refresh_token_cnt = await RefreshTokenRepository(db).delete_expired()

    logger.info(
        "cleanup_expired_tokens: removed %d authorization codes, %d refresh tokens",
        auth_code_cnt,
        refresh_token_cnt,
    )
