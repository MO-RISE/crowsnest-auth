from pathlib import Path

import pytest
import psycopg2
from sqlalchemy import create_engine

from app.models import User, users


def is_responsive(uri):
    try:
        conn = psycopg2.connect(uri)
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig):
    return Path(pytestconfig.rootdir) / "docker-compose.dev.yml"


@pytest.fixture(scope="session")
def pgdb(docker_ip, docker_services):
    """Ensure that the postgres db service is up and responsive."""

    # `port_for` takes a container port and returns the corresponding host port
    port = docker_services.port_for("postgres", 5432)
    uri = f"postgresql://test:test@{docker_ip}:{port}/test"
    docker_services.wait_until_responsive(
        timeout=30.0, pause=0.1, check=lambda: is_responsive(uri)
    )
    return uri


@pytest.fixture
def pgdb_connection(pgdb):
    engine = create_engine(pgdb)
    with engine.connect() as con:
        yield con


@pytest.fixture
def set_admin_user_fields(pgdb_connection):
    restore = {}

    def _(**field_names_values):
        nonlocal restore
        restore = dict.fromkeys(field_names_values, None)
        query = (
            users.update().where(User.username == "admin").values(**field_names_values)
        )
        pgdb_connection.execute(query)

    yield _

    restore_query = users.update().where(User.username == "admin").values(**restore)
    pgdb_connection.execute(restore_query)
