"""Compare the fp32 and int8 ONNX models on random standardized inputs."""
import numpy as np
import onnxruntime as ort

from ai.paths import ONNX_FP32_PATH, ONNX_INT8_PATH


def load_model(path):
    return ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])


def predict(session, x):
    name = session.get_inputs()[0].name
    return session.run(None, {name: x.astype(np.float32)})[0]


def main():
    fp32 = load_model(ONNX_FP32_PATH)
    int8 = load_model(ONNX_INT8_PATH)

    x = np.random.default_rng(42).normal(size=(1000, 4)).astype(np.float32)
    difference = np.abs(predict(fp32, x) - predict(int8, x))

    print("Maximum error:", difference.max())
    print("Mean error:", difference.mean())


if __name__ == "__main__":
    main()
