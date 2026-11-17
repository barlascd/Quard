"""Shared file locations. Override the model directory with QUARD_MODELS_DIR."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = Path(os.environ.get("QUARD_MODELS_DIR", ROOT / "models"))

SCALER_PATH = MODELS_DIR / "scaler.json"
TORCH_PATH = MODELS_DIR / "security_model.pth"
ONNX_FP32_PATH = MODELS_DIR / "security_model.onnx"
ONNX_INT8_PATH = MODELS_DIR / "security_model_int8.onnx"
