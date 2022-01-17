from pathlib import Path

import pytest
import requests
import psycopg2
from sqlalchemy import create_engine

from app.models import User, users


def postgres_is_responsive(uri):
    try:
        conn = psycopg2.connect(uri)
        return True
    except Exception:
        return False


def traefik_is_responsive(uri):
    return requests.get(uri).status_code != 404


@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig):
    return Path(pytestconfig.rootdir) / "docker-compose.dev.yml"


@pytest.fixture(scope="session")
def compose(docker_ip, docker_services):
    """Ensure that the postgres db service is up and responsive."""
    uris = {
        "postgres": f"postgresql://admin:password@{docker_ip}:{docker_services.port_for('auth_db', 5432)}/crowsnest_auth",
        "auth": f"http://{docker_ip}:7000/auth",
        "whoami": f"http://{docker_ip}:7000/whoami",
    }

    docker_services.wait_until_responsive(
        timeout=10.0, pause=0.1, check=lambda: postgres_is_responsive(uris["postgres"])
    )

    return uris


@pytest.fixture
def pgdb_connection(compose):
    engine = create_engine(compose["postgres"])
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
