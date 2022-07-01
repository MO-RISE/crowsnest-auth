import requests
import json
from app.models import User, users


def test_redirect(compose):

    # The client is redirected when requesting a protected resouce without providing a bearer token through a
    # cookie or header ...
    response = requests.get(compose["whoami"])
    assert response.status_code == 200
    assert response.history[0].status_code == 307

    # ... or when providing an invalid bearer token in a cookie ....
    response = requests.get(
        compose["whoami"], cookies={"crowsnest-auth-access": "bad_token"}
    )
    assert response.status_code == 200
    assert response.history[0].status_code == 307

    # ... but providing an invalid bearer token in a header does not redirects the client
    response = requests.get(
        compose["whoami"], headers={"Authorization": "Bearer bad_token"}
    )
    assert response.status_code == 401
    assert len(response.history) == 0


def test_api_login(compose):

    # A login request with wrong credentials ...
    response = requests.post(
        compose["auth"] + "/api/login", {"username": "admin", "password": "foo"}
    )

    # ... returns a status code HTTPError:400
    assert response.status_code == 400

    # A login request with the right credentials ...
    response = requests.post(
        compose["auth"] + "/api/login", {"username": "admin", "password": "password"}
    )

    # ... returns a status code 200:OK ...
    assert response.status_code == 200

    # ... and returns a cookie containing the bearer token ...
    cookies = response.cookies
    assert "crowsnest-auth-access" in cookies.get_dict()

    # ... as well as the bearer token in plain-text ...
    token = json.loads(response.text)
    assert "token" in token

    # Protected resources are accessible by with the cookie ...
    response = requests.get(compose["whoami"], cookies=cookies)
    assert response.status_code == 200
    assert len(response.history) == 0

    # ... or by providing the bearer token in the request headers
    response = requests.get(
        compose["whoami"],
        headers={
            "Authorization": f"Bearer {cookies.get_dict()['crowsnest-auth-access']}",
        },
    )
    assert response.status_code == 200
    assert len(response.history) == 0


def test_api_verify(compose, make_dummy_user, set_dummy_user_fields):

    # Log in as 'dummy_user'
    response = requests.post(
        compose["auth"] + "/api/login",
        {"username": "dummy_user", "password": "password"},
    )
    assert response.status_code == 200
    headers = {
        "Authorization": f"Bearer {response.cookies.get_dict()['crowsnest-auth-access']}",
    }

    # Add path whitelist to 'dummy_user'
    set_dummy_user_fields(path_whitelist=["/white"], path_blacklist=None)

    # Dummy can only access protected resource 'white' because its the only
    # whitelisted resource
    request = requests.get(compose["white"], headers=headers)
    assert request.status_code == 200
    request = requests.get(compose["black"], headers=headers)
    assert request.status_code == 401
    request = requests.get(compose["whoami"], headers=headers)
    assert request.status_code == 401

    # Dummy user has 'admin' set to false, so it cannot access protected
    # resources with 'admin' in the uri
    # request = requests.get(compose["auth"] + "/auth/admin", headers=headers)
    # assert request.status_code == 401
    # assert "Unauthorized access" in request.text

    # Add path blacklist to 'dummy_user'
    set_dummy_user_fields(path_whitelist=None, path_blacklist=["/black"])

    # Dummy can access all protected resources except 'black' because its the only
    # blacklisted resource
    request = requests.get(compose["white"], headers=headers)
    assert request.status_code == 200
    request = requests.get(compose["black"], headers=headers)
    assert request.status_code == 401
    request = requests.get(compose["whoami"], headers=headers)
    assert request.status_code == 200


"""




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
