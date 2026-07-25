import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest.joblib")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.joblib")

def generate_synthetic_data(n_normal=2000, n_anomaly=200):
    np.random.seed(42)

    # 1. Normal traffic features
    # payload_size (bytes), hour_of_day (0-23), day_of_week (0-6), freq_per_min, user_risk
    normal_payloads = np.random.exponential(scale=1500, size=n_normal) + 200 # ~200B to 5KB
    normal_hours = np.random.choice(np.arange(8, 19), size=n_normal) # Work hours 8am - 6pm
    normal_days = np.random.choice(np.arange(0, 5), size=n_normal) # Mon - Fri
    normal_freq = np.random.poisson(lam=3, size=n_normal) + 1 # 1-8 req/min
    normal_user_risk = np.random.beta(a=1.5, b=8, size=n_normal) * 0.3 # Low risk user history

    normal_df = pd.DataFrame({
        "payload_size": normal_payloads,
        "hour_of_day": normal_hours,
        "day_of_week": normal_days,
        "freq_per_min": normal_freq,
        "user_risk": normal_user_risk
    })

    # 2. Anomalous traffic features
    # Off-hours exfiltration, massive payloads, burst frequencies
    anomaly_payloads = np.random.uniform(50000, 1000000, size=n_anomaly) # 50KB to 1MB
    anomaly_hours = np.random.choice([0, 1, 2, 3, 4, 22, 23], size=n_anomaly) # Night hours
    anomaly_days = np.random.choice(np.arange(0, 7), size=n_anomaly)
    anomaly_freq = np.random.randint(25, 120, size=n_anomaly) # High burst speed
    anomaly_user_risk = np.random.uniform(0.6, 1.0, size=n_anomaly)

    anomaly_df = pd.DataFrame({
        "payload_size": anomaly_payloads,
        "hour_of_day": anomaly_hours,
        "day_of_week": anomaly_days,
        "freq_per_min": anomaly_freq,
        "user_risk": anomaly_user_risk
    })

    return normal_df, anomaly_df

def train_and_save_model():
    print("[ML Trainer] Generating synthetic normal and anomalous traffic datasets...")
    normal_df, anomaly_df = generate_synthetic_data()

    X_train = pd.concat([normal_df, anomaly_df], ignore_index=True)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    print("[ML Trainer] Training IsolationForest model...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42
    )
    model.fit(X_scaled)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print(f"[ML Trainer] Model successfully trained and saved to:\n - {MODEL_PATH}\n - {SCALER_PATH}")
    return model, scaler

if __name__ == "__main__":
    train_and_save_model()
