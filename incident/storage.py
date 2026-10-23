
import copy
import hashlib
import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from sqlalchemy import DateTime, JSON, String, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {},
)

SessionLocal = sessionmaker(
    bind=engine,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


class IncidentRun(Base):
    __tablename__ = "incident_runs"

    run_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


Base.metadata.create_all(engine)


def canonical_json(value) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def fingerprint(value) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def get_run(run_id: str):
    with SessionLocal() as session:
        row = session.get(IncidentRun, run_id)
        if row is None:
            return None
        return {
            "run_id": row.run_id,
            "request_hash": row.request_hash,
            "state": copy.deepcopy(row.state),
        }


def create_run(run_id: str, request_hash: str, initial_state: dict):
    """Insert a new run, or return the existing run without overwriting it."""
    try:
        with SessionLocal.begin() as session:
            row = IncidentRun(
                run_id=run_id,
                request_hash=request_hash,
                state=copy.deepcopy(initial_state),
            )
            session.add(row)
            session.flush()
        return True
    except IntegrityError:
        return False


def update_run(run_id: str, updater):
    """Serialize state transitions using a row lock on PostgreSQL."""
    with SessionLocal.begin() as session:
        stmt = (
            select(IncidentRun)
            .where(IncidentRun.run_id == run_id)
            .with_for_update()
        )
        row = session.execute(stmt).scalar_one_or_none()

        if row is None:
            return None

        state = copy.deepcopy(row.state)
        result = updater(state)

        row.state = state
        row.updated_at = datetime.now(timezone.utc)
        session.flush()

        return copy.deepcopy(result)


def replace_state(run_id: str, state: dict):
    with SessionLocal.begin() as session:
        row = session.get(IncidentRun, run_id)
        if row is None:
            return False

        row.state = copy.deepcopy(state)
        row.updated_at = datetime.now(timezone.utc)
        return True
