import pytest

from audit.db import build_database


@pytest.fixture(scope="session")
def db_urls():
    """Fresh databases for both policy sets, built once per test session."""
    return {name: build_database(name) for name in ("broken", "fixed")}
