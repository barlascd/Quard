from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from ai.inference import QuardAI

app = FastAPI(title="Quard AI Engine")
ai = QuardAI()


class SecurityRequest(BaseModel):
    features: list[float] = Field(min_length=4, max_length=4)


@app.get("/health")
def health():
    return {"status": "running", "engine": "QUARD AI"}


@app.post("/predict")
def predict(request: SecurityRequest):
    try:
        return {"risk_score": ai.predict(request.features)}
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Model not found. Run: python -m ai.train, ai.export_model, ai.quantize",
        )
