from fastapi.testclient import TestClient

from app.main import app


def test_creating_token_and_using_it(compose):
    with TestClient(app) as tc:
        response = tc.post("/login", {"username": "admin", "password": "admin"})
        assert response.status_code == 200, response.text
        cookies = response.cookies

        response = tc.get("/token", cookies=cookies)
        assert response.status_code == 404, response.text

        response = tc.post("/token", cookies=cookies)
        assert response.status_code == 200, response.text
        detail = response.json()
        assert "token" in detail

        response = tc.get("/token", cookies=cookies)
        assert response.status_code == 200, response.text
        assert response.json() == detail["token"]

        response = tc.get(
            "/verify",
            headers={
                "X-Forwarded-Host": "test",
                "X-Forwarded-Uri": "test",
                "Authorization": f"Bearer {detail['token']}",
            },
        )
        assert response.status_code == 200, response.text
