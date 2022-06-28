import requests
from fastapi.testclient import TestClient
from requests.models import Response

from app.main import app


def test_login_error_with_wrong_credentials(compose):
    response = requests.post(
        compose["auth"] + "/api/login", {"username": "admin", "password": "foo"}
    )
    assert response.status_code == 401
    # with TestClient(app) as tc:
    #    response = tc.post("/login", {"username": "admin", "password": "foo"})
    #    assert response.status_code == 401


def test_login_ok_with_right_credentials(compose):
    response = requests.post(
        compose["auth"] + "/api/login", {"username": "admin", "password": "password"}
    )
    print(response.cookies)
    assert response.status_code == 200
    assert response.cookies["crowsnest-auth-access"]
    # with TestClient(app) as tc:
    #    response = tc.post("/login", {"username": "admin", "password": "password"})
    #    assert response.status_code == 200
    #    assert response.cookies.get("crowsnest-auth-access") == "hey"


def test_verify_redirect_with_no_bearer_token_or_cookie(compose):
    with TestClient(app) as tc:
        response = tc.get(
            "/verify", headers={"X-Forwarded-Host": "test", "X-Forwarded-Uri": "test"}
        )
        # 404 because it can't find the page were it is redirected.
        assert response.status_code == 404, response.text


def test_verify_error_with_wrong_bearer_token(compose):
    with TestClient(app) as tc:
        response = tc.get(
            "/verify",
            headers={
                "X-Forwarded-Host": "test",
                "X-Forwarded-Uri": "test",
                "Authorization": "Bearer FunkyToken",
            },
        )
        assert response.status_code == 401, response.text


def test_verify_ok_with_right_cookie(compose):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "password"})
        cookies = response.cookies
        response = tc.get(
            "/verify",
            cookies=cookies,
            headers={"X-Forwarded-Host": "test", "X-Forwarded-Uri": "test"},
        )
        assert response.status_code == 200, response.text


def test_verify_ok_with_right_bearer_token(compose):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "password"})
        response = tc.get(
            "/verify",
            headers={
                "X-Forwarded-Host": "test",
                "X-Forwarded-Uri": "test",
                "Authorization": f"Bearer {response.cookies['crowsnest-auth-access']}",
            },
        )
        assert response.status_code == 200


def test_access_is_denied_with_funky_token_in_headers(compose):
    with TestClient(app) as tc:
        response = tc.get("/verify", headers={"Authorization": "Bearer FunkyToken"})
        assert response.status_code == 401, response.text


"""

# def test_access_is_denied_with_funky_token_in_cookie(compose):
#     # Denied access redirects
#     with TestClient(app) as tc:
#         response = tc.get("/verify", cookies={"crowsnest-auth-access": "FunkyToken"})
#         print(response)
#         assert response.status_code == 200


def test_access_is_allowed_with_cookie_when_logged_in(compose):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "password"})
        assert response.status_code == 200, response.text
        response = tc.get(
            "/verify",
            cookies=response.cookies,
            headers={"X-Forwarded-Host": "test", "X-Forwarded-Uri": "test"},
        )
        assert response.status_code == 200, response.text


def test_access_is_allowed_with_bearer_header_when_logged_in(compose):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "password"})
        assert response.status_code == 200, response.text
        print(response.status_code)
        print(response.cookies["crowsnest-auth-access"])
        response = tc.get(
            "/verify",
            headers={
                "X-Forwarded-Host": "test",
                "X-Forwarded-Uri": "test",
                "Authorization": f"Bearer {response.cookies['crowsnest-auth-access']}",
            },
        )
        assert response.status_code == 200, response.text


def test_verify_complains_when_X_forwarded_headers_are_missing(compose):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "admin"})
        assert response.status_code == 200, response.text

        response = tc.get(
            "/verify",
            cookies=response.cookies,
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Missing required X-Forwarded-Headers"}


def test_verify_path_whitelist(compose, set_admin_user_fields):
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


def test_verify_path_blacklist(compose, set_admin_user_fields):
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


def test_verify_emqx(compose):
    with TestClient(app) as tc:

        response = tc.get(
            "/verify_emqx",
            params={
                "username": "admin",
                "topic": "any/trial/topic",
            },
        )
        assert response.status_code == 200


def test_verify_emqx_topic_whitelist(compose, set_admin_user_fields):
    set_admin_user_fields(topic_whitelist=["any/+/topic/#"])
    with TestClient(app) as tc:

        response = tc.get(
            "/verify_emqx",
            params={"username": "admin", "topic": "any/trial/topic"},
        )
        assert response.status_code == 200, response.text

        response = tc.get(
            "/verify_emqx",
            params={"username": "admin", "topic": "any/trial/"},
        )
        assert response.status_code == 403, response.text


def test_verify_emqx_topic_blacklist(compose, set_admin_user_fields):
    set_admin_user_fields(topic_blacklist=["any/+/topic/#"])
    with TestClient(app) as tc:

        response = tc.get(
            "/verify_emqx",
            params={"username": "admin", "topic": "something/else/trial/topic"},
        )
        assert response.status_code == 200, response.text

        response = tc.get(
            "/verify_emqx",
            params={"username": "admin", "topic": "any/trial/topic/"},
        )
        assert response.status_code == 403, response.text
"""
