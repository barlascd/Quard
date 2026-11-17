from onnxruntime.quantization import QuantType, quantize_dynamic

from ai.paths import ONNX_FP32_PATH, ONNX_INT8_PATH

if __name__ == "__main__":
    quantize_dynamic(
        model_input=str(ONNX_FP32_PATH),
        model_output=str(ONNX_INT8_PATH),
        weight_type=QuantType.QInt8,
    )
