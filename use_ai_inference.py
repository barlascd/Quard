"""Run from the repo root:  python -m examples.use_ai_inference"""
from ai.inference import QuardAI

ai = QuardAI()
risk = ai.predict([0.8, 0.9, 0.7, 0.5])
print("Risk score", risk)
