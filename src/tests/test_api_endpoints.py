import pytest
from src.api.app import app
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import time

client = TestClient(app)

@pytest.fixture(scope="module")
def test_client():
    return client

def test_health_endpoint(test_client):
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_metrics_endpoint(test_client):
    response = test_client.get("/metrics")
    assert response.status_code == 200
    # Ensure Prometheus metric is present
    assert b"http_requests_total" in response.content

def test_channels_endpoint(test_client):
    response = test_client.get("/channels")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data.get("channels"), list)
    assert isinstance(data.get("stats"), dict)

def test_manager_start_stop(test_client):
    resp_stop = test_client.post("/manager/stop")
    assert resp_stop.status_code == 200
    assert resp_stop.json().get("manager_stopped") is True

    resp_start = test_client.post("/manager/start")
    assert resp_start.status_code == 200
    assert resp_start.json().get("manager_started") in (True, False)  # may already be running 