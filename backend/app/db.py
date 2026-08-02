from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings


def _ensure_sqlite_parent(url: str) -> None:
    """Create the parent directory for a file-backed SQLite database."""
    if url.startswith("sqlite:///"):
        path = url[len("sqlite:///") :]
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)


class Base(DeclarativeBase):
    pass


_connect_args: dict = {}
if settings.database_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

_ensure_sqlite_parent(settings.database_url)
engine = create_engine(settings.database_url, connect_args=_connect_args)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _connection_record) -> None:
    """SQLite does not enforce foreign keys by default; MASA relies on ON DELETE CASCADE."""
    if settings.database_url.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
