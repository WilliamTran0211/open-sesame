from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.redis import RedisClient
from app.jobs.cleanup import cleanup_expired_tokens

scheduler = AsyncIOScheduler()


def setup_scheduler(redis_client: RedisClient) -> None:
    scheduler.add_job(
        cleanup_expired_tokens,
        trigger=IntervalTrigger(hours=1),
        args=[redis_client],
        id="cleanup_expired_tokens",
        max_instances=1,  # không cho 2 lần chạy chồng nhau dù cùng 1 worker
        coalesce=True,  # nếu có miss nhiều lần thì chỉ chạy lại 1 lần
        misfire_grace_time=300,
    )

    scheduler.start()
