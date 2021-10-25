from fastapi.testclient import TestClient

from app.main import app


def test_access_is_denied_without_logging_in(pgdb):
    with TestClient(app) as tc:
        response = tc.get("/verify")
        assert response.status_code == 401, response.text


def test_access_is_denied_with_funky_token_in_headers(pgdb):
    with TestClient(app) as tc:
        response = tc.get("/verify", headers={"Authorization": "Bearer FunkyToken"})
        assert response.status_code == 401, response.text


def test_access_is_denied_with_funky_token_in_cookie(pgdb):
    with TestClient(app) as tc:
        response = tc.get("/verify", cookies={"crowsnest-auth-access": "FunkyToken"})
        assert response.status_code == 401, response.text


def test_access_is_allowed_with_cookie_when_logged_in(pgdb):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "admin"})
        assert response.status_code == 200, response.text

        response = tc.get(
            "/verify",
            cookies=response.cookies,
            headers={"X-Forwarded-Host": "test", "X-Forwarded-Uri": "test"},
        )
        assert response.status_code == 200, response.text


def test_access_is_allowed_with_bearer_header_when_logged_in(pgdb):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "admin"})
        assert response.status_code == 200, response.text

        response = tc.get(
            "/verify",
            headers={
                "X-Forwarded-Host": "test",
                "X-Forwarded-Uri": "test",
                "Authorization": f"Bearer {response.cookies['crowsnest-auth-access']}",
            },
        )
        assert response.status_code == 200, response.text


def test_verify_complains_when_X_forwarded_headers_are_missing(pgdb):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "admin"})
        assert response.status_code == 200, response.text

        response = tc.get(
            "/verify",
            cookies=response.cookies,
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Missing required X-Forwarded-Headers"}


def test_verify_path_whitelist(pgdb, set_admin_user_fields):
    set_admin_user_fields(path_whitelist=["/test"])
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "admin"})
        assert response.status_code == 200, response.text

        # Should work
        response = tc.get(
            "/verify",
            cookies=response.cookies,
            headers={"X-Forwarded-Host": "test", "X-Forwarded-Uri": "/test"},
        )
        assert response.status_code == 200, response.text

        # Should not work
        response = tc.get(
            "/verify",
            cookies=response.cookies,
            headers={"X-Forwarded-Host": "test", "X-Forwarded-Uri": "/not_test"},
        )
        assert response.status_code == 403, response.text


def test_verify_path_blacklist(pgdb, set_admin_user_fields):
    set_admin_user_fields(path_blacklist=["/test"])
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "admin"})
        assert response.status_code == 200, response.text

        # Should work
        response = tc.get(
            "/verify",
            cookies=response.cookies,
            headers={"X-Forwarded-Host": "test", "X-Forwarded-Uri": "/anything"},
        )
        assert response.status_code == 200, response.text

        # Should not work
        response = tc.get(
            "/verify",
            cookies=response.cookies,
            headers={"X-Forwarded-Host": "test", "X-Forwarded-Uri": "/test"},
        )
        assert response.status_code == 403, response.text
