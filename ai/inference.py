import json
import threading

import numpy as np
import onnxruntime as ort

from ai.paths import ONNX_INT8_PATH, SCALER_PATH
from ai.preprocessing import validate_features


class QuardAI:
    """Risk scorer. Loads the model lazily, so constructing it never fails
    when model files are missing; `predict` raises FileNotFoundError instead."""

    def __init__(self, model_path=None, scaler_path=None):
        self.model_path = str(model_path or ONNX_INT8_PATH)
        self.scaler_path = str(scaler_path or SCALER_PATH)
        self._lock = threading.Lock()
        self._loaded = None

    def _load(self):
        with self._lock:
            if self._loaded is None:
                with open(self.scaler_path) as f:
                    scaler = json.load(f)
                session = ort.InferenceSession(
                    self.model_path, providers=["CPUExecutionProvider"]
                )
                self._loaded = (
                    np.asarray(scaler["mean"], dtype=np.float32),
                    np.asarray(scaler["scale"], dtype=np.float32),
                    session,
                    session.get_inputs()[0].name,
                    session.get_outputs()[0].name,
                )
        return self._loaded

    def predict(self, features) -> float:
        """Risk score in [0, 1]. Raises ValueError on invalid input."""
        x = validate_features(features)  # validate before touching the model
        mean, scale, session, input_name, output_name = self._load()
        x = ((x - mean) / np.where(scale == 0, 1, scale)).astype(np.float32)
        result = session.run([output_name], {input_name: x})
        score = float(np.asarray(result[0]).reshape(-1)[0])
        if not np.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("Invalid model output")
        return score


_default = QuardAI()


def predict(features) -> float:
    """Module-level shortcut using the default model."""
    return _default.predict(features)
