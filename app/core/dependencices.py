from typing import Optional

from fastapi import Depends

from app.core.redis import RedisClient

_redis_client: Optional[RedisClient] = None


async def get_redis_client() -> RedisClient:
    global _redis_client
    if _redis_client is None:
        _redis_client = RedisClient()
        await _redis_client.connect()
        return _redis_client
    return _redis_client
