import os
import joblib
import pandas as pd

MODEL_PATH = os.path.join("models", "session_model.pkl")


def ai_predict(login_data):
    if not os.path.exists(MODEL_PATH):
        return {
            "ai_available": False,
            "ai_prediction": "Model not trained",
            "ai_risk": 0
        }

    model = joblib.load(MODEL_PATH)

    df = pd.DataFrame([{
        "login_hour": login_data["login_time"].hour,
        "device_code": abs(hash(login_data["device"])) % 1000,
        "browser_code": abs(hash(login_data["browser"])) % 1000,
        "ip_code": abs(hash(login_data["ip_address"])) % 1000,
        "session_code": abs(hash(login_data["session_hash"])) % 1000
    }])

    prediction = model.predict(df)[0]

    probability = model.predict_proba(df)[0]

    suspicious_probability = probability[1] if len(probability) > 1 else 0

    return {
        "ai_available": True,
        "ai_prediction": "Suspicious" if prediction == 1 else "Normal",
        "ai_risk": round(suspicious_probability * 100, 2)
    }