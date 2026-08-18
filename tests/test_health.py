import pytest

from backend.app import create_app
from backend.config import TestConfig


@pytest.fixture
def app():
    return create_app(TestConfig)


@pytest.fixture
def client(app):
    return app.test_client()


def test_create_app_works(app):
    assert app is not None


def test_health_returns_200(client):
    response = client.get("/api/health")
    assert response.status_code == 200


def test_health_response_body(client):
    response = client.get("/api/health")
    data = response.get_json()
    assert data["success"] is True
    assert data["status"] == "healthy"
