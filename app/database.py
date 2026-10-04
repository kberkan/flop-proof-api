import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# FLOP_DATABASE_URL selects the database; without it the API uses ./proofs.db
# as before. The engine below is created when this module is first imported,
# so the variable must be set before anything imports app.database (app.main
# included); setting it later has no effect. scripts/run_tests.sh sets it for
# both the test server and pytest.
DATABASE_URL = os.getenv("FLOP_DATABASE_URL", "sqlite:///./proofs.db")

engine = create_engine(
    DATABASE_URL,
    # SQLite only: the API uses sessions from several threads.
    connect_args=(
        {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    ),
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
