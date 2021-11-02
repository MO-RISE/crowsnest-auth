import requests
import pytest
from paho.mqtt import subscribe, publish, MQTTException


def test_http_through_traefik(compose):
    response = requests.get(compose["whoami"])
    assert response.status_code == 401, response.text

    response = requests.post(
        f"{compose['auth']}/login", {"username": "admin", "password": "admin"}
    )
    assert response.status_code == 200, response.text

    response = requests.get(compose["whoami"], cookies=response.cookies)
    assert response.status_code == 200, response.text


def test_mqtt_over_tcp_through_traefik(compose):

    with pytest.raises(MQTTException):
        publish.single("topic", "payload", hostname="localhost", port=1883)

    publish.single(
        "topic",
        "payload",
        hostname="localhost",
        port=1883,
        auth={"username": "admin", "password": "admin"},
    )
