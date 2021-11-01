import requests


def test_http_through_traefik(compose):
    response = requests.get(compose["whoami"])
    assert response.status_code == 401, response.text
