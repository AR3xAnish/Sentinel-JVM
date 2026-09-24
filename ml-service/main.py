import os
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from model_trainer import train_and_save_model, MODEL_PATH, SCALER_PATH

app = FastAPI(
    title="Sentinel-JVM Content & Semantic Analysis Service",
    description="Microservice for semantic content classification and anomaly scoring",
    version="2.0.0"
)

# Global variables for model and scaler
model = None
scaler = None

def load_model_and_scaler():
    global model, scaler
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            print("[ML Service] Loaded pre-trained model and scaler.")
        except Exception as e:
            print(f"[ML Service] Error loading saved model: {e}. Retraining now...")
            model, scaler = train_and_save_model()
    else:
        print("[ML Service] No saved model found. Training initial model...")
        model, scaler = train_and_save_model()

@app.on_event("startup")
def startup_event():
    load_model_and_scaler()

class ScoreRequest(BaseModel):
    destinationHost: Optional[str] = "api.openai.com"
    payloadSize: int = Field(..., description="Payload size in bytes")
    hourOfDay: int = Field(12, ge=0, le=23, description="Hour of the day (0-23)")
    dayOfWeek: int = Field(0, ge=0, le=6, description="Day of week (0=Mon, 6=Sun)")
    frequencyPerMinute: int = Field(1, ge=0, description="Request frequency per minute")
    userHistoricalRisk: float = Field(0.1, ge=0.0, le=1.0, description="User historical risk score")
    bodyText: Optional[str] = Field(None, description="Optional payload body text for semantic analysis")

class ScoreResponse(BaseModel):
    anomalyScore: float = Field(..., description="Normalized semantic & behavioral anomaly score between 0.0 and 1.0")
    isAnomaly: bool = Field(..., description="True if anomaly decision threshold is exceeded")
    semanticCategory: Optional[str] = Field("GENERAL_QUERY", description="Detected semantic content category")
    details: Dict[str, Any]

@app.get("/health")
def health_check():
    return {"status": "healthy", "modelLoaded": model is not None}

@app.post("/score", response_model=ScoreResponse)
def score_payload(req: ScoreRequest):
    global model, scaler
    if model is None or scaler is None:
        load_model_and_scaler()

    df = pd.DataFrame([{
        "payload_size": req.payloadSize,
        "hour_of_day": req.hourOfDay,
        "day_of_week": req.dayOfWeek,
        "freq_per_min": req.frequencyPerMinute,
        "user_risk": req.userHistoricalRisk
    }])

    try:
        scaled_features = scaler.transform(df)
        decision = float(model.decision_function(scaled_features)[0])
        prediction = int(model.predict(scaled_features)[0])

        if decision >= 0:
            norm_anomaly_score = float(np.clip(0.10 - (decision * 0.5), 0.05, 0.25))
        else:
            norm_anomaly_score = float(np.clip(0.25 + (abs(decision) * 1.5), 0.26, 0.90))

        # Perform basic semantic classification on text if provided
        body = req.bodyText or ""
        semantic_cat = "GENERAL_QUERY"
        if "CONFIDENTIAL" in body.upper() or "PROPRIETARY" in body.upper():
            semantic_cat = "BUSINESS_CONFIDENTIAL"
            norm_anomaly_score = max(norm_anomaly_score, 0.85)
        elif "class " in body or "def " in body or "function " in body or "SELECT " in body:
            semantic_cat = "SOURCE_CODE"
            norm_anomaly_score = max(norm_anomaly_score, 0.70)

        is_anomaly = bool(prediction == -1 or norm_anomaly_score > 0.65)

        return ScoreResponse(
            anomalyScore=round(norm_anomaly_score, 4),
            isAnomaly=is_anomaly,
            semanticCategory=semantic_cat,
            details={
                "model_decision_score": round(decision, 4),
                "is_outlier": bool(prediction == -1),
                "payload_size": int(req.payloadSize),
                "destination": str(req.destinationHost)
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

@app.post("/train")
def train_model_endpoint():
    global model, scaler
    model, scaler = train_and_save_model()
    return {"status": "success", "message": "Content classification model retrained successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
