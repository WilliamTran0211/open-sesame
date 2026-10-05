from fastapi import Depends, Request

from app.api.deps import CurrentUserDep
from app.common.error_message import ErrorMessage
from app.core.deps import RedisDep
from app.core.exception import RateLimitError
from app.core.redis import RedisClient


def rate_limit(
    key_prefix: str,
    identifier_field: str | None = None,
    limit: int = 20,
    window_seconds: int = 300,
):
    async def dependency(request: Request, redis_client: RedisDep):
        ip = request.client.host
        identifier = ip
        if identifier_field:
            try:
                body = await request.json()
            except ValueError:
                body = {}
            identifier = f"{ip}:{body.get(identifier_field, '')}"

        key = f"rate_limit:{key_prefix}:{identifier}"
        count = await redis_client.incr(key)
        if count == 1:
            await redis_client.expire(key, window_seconds)
        if count > limit:
            raise RateLimitError(ErrorMessage.RATE_LIMITED)

    return Depends(dependency)


async def record_auth_failure(
    request: Request,
    redis_client: RedisClient,
    key_prefix: str,
    identifier: str,
    limit: int = 20,
    window_seconds: int = 300,
) -> None:
    """Only count failed auth attempts."""
    ip = request.client.host
    key = f"rate_limit:{key_prefix}:{ip}:{identifier}"
    count = await redis_client.incr(key)
    if count == 1:
        await redis_client.expire(key, window_seconds)
    if count > limit:
        raise RateLimitError(ErrorMessage.RATE_LIMITED)


def rate_limit_by_user(key_prefix: str, limit: int = 20, window_seconds: int = 300):
    async def dependency(current_user: CurrentUserDep, redis_client: RedisDep):
        key = f"rate_limit:{key_prefix}:{current_user.id}"
        count = await redis_client.incr(key)
        if count == 1:
            await redis_client.expire(key, window_seconds)
        if count > limit:
            raise RateLimitError(ErrorMessage.RATE_LIMITED)

    return Depends(dependency)
