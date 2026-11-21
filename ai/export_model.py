import torch

from ai.model import SecurityModel
from ai.paths import ONNX_FP32_PATH, TORCH_PATH


def export_model():
    model = SecurityModel()
    model.load_state_dict(
        torch.load(TORCH_PATH, map_location="cpu", weights_only=True)
    )
    model.eval()

    example = torch.zeros(1, 4, dtype=torch.float32)
    torch.onnx.export(
        model,
        (example,),
        str(ONNX_FP32_PATH),
        input_names=["features"],
        output_names=["risk_score"],
        dynamic_axes={"features": {0: "batch"}, "risk_score": {0: "batch"}},
        dynamo=False,
        opset_version=17,
    )


if __name__ == "__main__":
    export_model()
