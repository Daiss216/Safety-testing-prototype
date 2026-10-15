import os
import time

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./bayora.db")

_engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def ensure_schema(retries: int = 12, delay: float = 0.25) -> None:
    """Idempotent create. Concurrent workers can race on first boot."""
    last: Exception | None = None
    for _ in range(retries):
        try:
            Base.metadata.create_all(engine)
            return
        except (OperationalError, ProgrammingError) as exc:
            last = exc
            time.sleep(delay)
    if last:
        raise last