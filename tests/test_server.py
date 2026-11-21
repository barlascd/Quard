import pytest
from fastapi.testclient import TestClient

from ai.paths import ONNX_INT8_PATH, SCALER_PATH
from ai.server import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "running", "engine": "QUARD AI"}


def test_wrong_length_is_422():
    assert client.post("/predict", json={"features": [1, 2, 3]}).status_code == 422


def test_negative_is_400():
    r = client.post("/predict", json={"features": [10, -1, 0.2, 5]})
    assert r.status_code == 400


@pytest.mark.skipif(not ONNX_INT8_PATH.exists() or not SCALER_PATH.exists(),
                    reason="model not built")
def test_predict_ok():
    r = client.post("/predict", json={"features": [10, 0, 0.2, 5]})
    assert r.status_code == 200
    assert 0 <= r.json()["risk_score"] <= 1
