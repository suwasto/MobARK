import time

import pytest

from app.workers.jobs import dummy_job, enqueue_dummy

pytestmark = pytest.mark.integration


def test_dummy_job_returns_expected_result():
    # Direct call - no Redis needed.
    assert dummy_job("direct") == {"echo": "direct", "processed": True, "status": "ok"}


def test_dummy_job_round_trip_via_rq():
    """M0 acceptance: enqueue -> worker processes -> job finished with result.

    Requires Redis reachable at MASA_REDIS_URL and a running RQ worker, e.g.:
        docker compose up -d redis worker
    or, with a local Redis:  python worker.py
    """
    job = enqueue_dummy("integration check")

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        job.refresh()
        if job.get_status() in ("finished", "failed"):
            break
        time.sleep(0.5)

    assert job.get_status() == "finished", f"job not finished; last status: {job.get_status()}"
    assert job.return_value() == {"echo": "integration check", "processed": True, "status": "ok"}
