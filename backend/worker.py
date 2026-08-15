"""RQ worker entrypoint.

Run with:  python worker.py
(MobARK Docker Compose starts this for the `worker` service.)
"""

from rq import Queue, Worker

from app.workers.jobs import DEFAULT_QUEUE  # also registers the job functions
from app.workers.redis import get_redis


def main() -> None:
    # RQ 2.0 removed the legacy Connection context manager; pass the
    # connection directly to the Queue/Worker instead.
    worker = Worker(Queue(DEFAULT_QUEUE, connection=get_redis()))
    worker.work()


if __name__ == "__main__":
    main()
