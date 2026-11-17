from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from ai.inference import predict

app = FastAPI(title="Quard AI service")


class SecurityInput(BaseModel):
    features: list[float] = Field(min_length=4, max_length=4)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict")
def analyze(data: SecurityInput):
    try:
        return {"risk_score": predict(data.features)}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Model not found. Run: python -m ai.train, ai.export_model, ai.quantize",
        )
