import time

from rq import Queue

from app.workers.redis import get_redis

DEFAULT_QUEUE = "default"


def dummy_job(message: str = "hello from MASA") -> dict:
    """M0 smoke-test job: proves the Redis -> RQ -> worker -> result loop.

    Replaced by real scan jobs in M1.
    """
    time.sleep(0.5)
    return {"echo": message, "processed": True, "status": "ok"}


def enqueue_dummy(message: str = "hello from MASA"):
    """Enqueue the dummy job and return the RQ Job handle."""
    queue = Queue(DEFAULT_QUEUE, connection=get_redis())
    return queue.enqueue(dummy_job, message)
