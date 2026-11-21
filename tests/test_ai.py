import numpy as np
import pytest

from ai.inference import QuardAI, predict
from ai.paths import ONNX_INT8_PATH, SCALER_PATH

needs_model = pytest.mark.skipif(
    not (ONNX_INT8_PATH.exists() and SCALER_PATH.exists()),
    reason="model not built (run ai.train, ai.export_model, ai.quantize)",
)


@needs_model
def test_valid_input():
    result = predict([10, 0, 0.2, 5])
    assert 0 <= result <= 1


@needs_model
def test_attack_scores_higher_than_normal():
    assert predict([90, 20, 0.95, 60]) > predict([10, 0, 0.2, 5])


def test_nan_input():
    with pytest.raises(ValueError):
        predict([10, np.nan, 0.2, 5])


def test_inf_input():
    with pytest.raises(ValueError):
        predict([10, np.inf, 0.2, 5])


def test_negative_input():
    with pytest.raises(ValueError):
        predict([10, -1, 0.2, 5])


def test_invalid_cpu():
    with pytest.raises(ValueError):
        predict([10, 0, 1.5, 5])


def test_wrong_length():
    with pytest.raises(ValueError):
        predict([1, 2, 3])


@needs_model
def test_quardai_class_matches_module_function():
    assert QuardAI().predict([10, 0, 0.2, 5]) == predict([10, 0, 0.2, 5])


def test_quardai_construction_needs_no_model(tmp_path):
    ai = QuardAI(tmp_path / "missing.onnx", tmp_path / "missing.json")
    with pytest.raises(ValueError):          # validation runs first
        ai.predict([1, 2, 3])
    with pytest.raises(FileNotFoundError):   # valid input, no model files
        ai.predict([10, 0, 0.2, 5])
