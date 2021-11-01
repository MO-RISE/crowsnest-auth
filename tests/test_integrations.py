import requests


def test_http_through_traefik(compose):
    response = requests.get(compose["whoami"])
    assert response.status_code == 401, response.text

    response = requests.post(
        f"{compose['auth']}/login", {"username": "admin", "password": "admin"}
    )
    assert response.status_code == 200, response.text

    response = requests.get(compose["whoami"], cookies=response.cookies)
    assert response.status_code == 200, response.text
