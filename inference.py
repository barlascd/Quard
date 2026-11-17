import json
import threading

import numpy as np
import onnxruntime as ort

from ai.paths import ONNX_INT8_PATH, SCALER_PATH
from ai.preprocessing import validate_features

_lock = threading.Lock()
_state = None


def _load():
    """Load model and scaler on first use, so importing never needs model files."""
    global _state
    with _lock:
        if _state is None:
            with open(SCALER_PATH) as f:
                scaler = json.load(f)
            session = ort.InferenceSession(
                str(ONNX_INT8_PATH), providers=["CPUExecutionProvider"]
            )
            _state = (
                np.asarray(scaler["mean"], dtype=np.float32),
                np.asarray(scaler["scale"], dtype=np.float32),
                session,
                session.get_inputs()[0].name,
            )
    return _state


def predict(features) -> float:
    """Return a risk score in [0, 1]. Raises ValueError on invalid input,
    FileNotFoundError if the model has not been trained/exported yet."""
    x = validate_features(features)  # validate before touching the model

    mean, scale, session, input_name = _load()
    x = ((x - mean) / np.where(scale == 0, 1, scale)).astype(np.float32)
    result = session.run(None, {input_name: x})[0]

    score = float(result.reshape(-1)[0])
    if not np.isfinite(score) or not 0 <= score <= 1:
        raise ValueError("Invalid model output")
    return score
