import os
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from model_trainer import train_and_save_model, MODEL_PATH, SCALER_PATH

app = FastAPI(
    title="Sentinel-JVM ML Anomaly Detection Service",
    description="IsolationForest microservice for Shadow AI behavioral anomaly scoring",
    version="1.0.0"
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
            print("[ML Service] Loaded pre-trained IsolationForest model and scaler.")
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

class ScoreResponse(BaseModel):
    anomalyScore: float = Field(..., description="Normalized anomaly score between 0.0 and 1.0")
    isAnomaly: bool = Field(..., description="True if anomaly decision threshold is exceeded")
    details: Dict[str, Any]

@app.get("/health")
def health_check():
    return {"status": "healthy", "modelLoaded": model is not None}

@app.post("/score", response_model=ScoreResponse)
def score_payload(req: ScoreRequest):
    global model, scaler
    if model is None or scaler is None:
        load_model_and_scaler()

    # Prepare feature vector
    df = pd.DataFrame([{
        "payload_size": req.payloadSize,
        "hour_of_day": req.hourOfDay,
        "day_of_week": req.dayOfWeek,
        "freq_per_min": req.frequencyPerMinute,
        "user_risk": req.userHistoricalRisk
    }])

    try:
        scaled_features = scaler.transform(df)
        decision = float(model.decision_function(scaled_features)[0]) # > 0 is normal, < 0 is anomaly
        prediction = int(model.predict(scaled_features)[0]) # -1 for anomaly, 1 for normal

        # Convert IsolationForest decision function (> 0 normal, < 0 anomaly) to 0.0 - 1.0 risk score
        if decision >= 0:
            norm_anomaly_score = float(np.clip(0.30 - (decision * 1.2), 0.05, 0.35))
        else:
            norm_anomaly_score = float(np.clip(0.35 + (abs(decision) * 2.2), 0.36, 1.0))

        is_anomaly = bool(prediction == -1 or norm_anomaly_score > 0.65)

        return ScoreResponse(
            anomalyScore=round(norm_anomaly_score, 4),
            isAnomaly=is_anomaly,
            details={
                "decision_function_score": round(decision, 4),
                "is_isolation_outlier": bool(prediction == -1),
                "payload_size": int(req.payloadSize),
                "hour_of_day": int(req.hourOfDay),
                "destination": str(req.destinationHost)
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

@app.post("/train")
def train_model_endpoint():
    global model, scaler
    model, scaler = train_and_save_model()
    return {"status": "success", "message": "IsolationForest model retrained successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
