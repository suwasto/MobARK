import redis

from app.config import settings

# Note: decode_responses intentionally left off. RQ stores job payloads as
# pickled bytes; a decoding connection would corrupt them on read-back.
_redis: redis.Redis | None = None


def get_redis() -> redis.Redis:
    """Return the shared Redis client (lazily created)."""
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(settings.redis_url)
    return _redis
