from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime

from train import train_model
from database import get_connection
from learning import LEARNING_LIMIT, update_user_behavior, calculate_risk
from predictor import ai_predict

app = FastAPI()


class LoginRequest(BaseModel):
    user_id: str
    login_time: str
    ip_address: str
    device: str
    browser: str
    session_hash: str


@app.get("/")
def home():
    return {"message": "AI Session Hijacking Detector API is running"}


@app.post("/predict")
def predict_login(data: LoginRequest):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    login_time = datetime.fromisoformat(data.login_time.replace("Z", ""))

    cursor.execute("SELECT * FROM user_behavior WHERE user_id = %s", (data.user_id,))
    behavior = cursor.fetchone()

    if behavior is None or behavior["login_count"] < LEARNING_LIMIT:
        risk_score = 0
        status = "Learning"
        reason = "User is still in learning mode"
        action = "Allow"
    else:
        login_data = {
            "user_id": data.user_id,
            "login_time": login_time,
            "ip_address": data.ip_address,
            "device": data.device,
            "browser": data.browser,
            "session_hash": data.session_hash
        }

        rule_risk, rule_status, rule_reason, rule_action = calculate_risk(login_data, behavior)
        ai_result = ai_predict(login_data)

        if ai_result["ai_available"]:
            ai_risk = ai_result["ai_risk"]
            risk_score = int((rule_risk + ai_risk) / 2)
            reason = f"Rule: {rule_reason} | AI: {ai_result['ai_prediction']} ({ai_risk}%)"

            if risk_score >= 70:
                status = "Suspicious"
                action = "Block Session"
            elif risk_score >= 40:
                status = "Suspicious"
                action = "Force Re-login"
            else:
                status = "Normal"
                action = "Allow"
        else:
            risk_score = rule_risk
            status = rule_status
            reason = rule_reason
            action = rule_action

    cursor.execute("""
        INSERT INTO login_events (
            user_id, login_time, ip_address, device, browser,
            session_hash, risk_score, status, reason, action
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        data.user_id, login_time, data.ip_address, data.device,
        data.browser, data.session_hash, risk_score, status, reason, action
    ))

    if status in ["Learning", "Normal"]:
        update_user_behavior(cursor, data.user_id)

    if status == "Suspicious":
        cursor.execute("""
            INSERT INTO alerts (user_id, risk_score, reason, action_taken)
            VALUES (%s,%s,%s,%s)
        """, (data.user_id, risk_score, reason, action))

    conn.commit()
    cursor.close()
    conn.close()

    return {
        "mode": "Learning" if status == "Learning" else "Detection",
        "user_id": data.user_id,
        "risk_score": risk_score,
        "status": status,
        "reason": reason,
        "action": action
    }


@app.post("/train")
def train_ai_model():
    return train_model()