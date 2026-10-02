from fastapi import Depends, Request


from app.common.error_message import ErrorMessage
from app.core.deps import RedisDep
from app.core.exception import RateLimitError


def rate_limit(
    key_prefix: str,
    identifier_field: str | None = None,
    limit: int = 5,
    window_seconds: int = 300,
):
    async def dependency(request: Request, redis_client: RedisDep):
        ip = request.client.host
        identifier = ip
        if identifier_field:
            body = await request.json()
            identifier = f"{ip}:{body.get(identifier_field, '')}"

        key = f"rate_limit:{key_prefix}:{identifier}"
        count = await redis_client.incr(key)
        if count == 1:
            await redis_client.expire(key, window_seconds)
        if count > limit:
            raise RateLimitError(ErrorMessage.RATE_LIMITED)

    return Depends(dependency)
