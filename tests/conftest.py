from pathlib import Path

import pytest

from database import SessionLocal, engine
import models


@pytest.fixture
def db():
    models.Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def pcap_path():
    path = Path(__file__).resolve().parents[1] / "datasets" / "sample.pcap"
    if not path.is_file():
        pytest.fail(f"Sample PCAP is not available: {path}")
    return str(path)
