import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

from database import get_connection

MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "session_model.pkl")


def train_model():
    conn = get_connection()

    query = """
        SELECT 
            user_id,
            HOUR(login_time) AS login_hour,
            ip_address,
            device,
            browser,
            session_hash,
            status
        FROM login_events
        WHERE status IN ('Normal', 'Suspicious', 'Learning')
    """

    df = pd.read_sql(query, conn)
    conn.close()

    if df.empty:
        return {
            "status": "failed",
            "message": "No login records found"
        }

    # Treat Learning and Normal as normal class
    df["label"] = df["status"].apply(lambda x: 1 if x == "Suspicious" else 0)

    # Convert text columns into numeric features
    df["device_code"] = df["device"].astype("category").cat.codes
    df["browser_code"] = df["browser"].astype("category").cat.codes
    df["ip_code"] = df["ip_address"].astype("category").cat.codes
    df["session_code"] = df["session_hash"].astype("category").cat.codes

    X = df[[
        "login_hour",
        "device_code",
        "browser_code",
        "ip_code",
        "session_code"
    ]]

    y = df["label"]

    if len(df) < 10:
        return {
            "status": "failed",
            "message": "Not enough records to train model"
        }

    if y.nunique() < 2:
        return {
            "status": "failed",
            "message": "Need both Normal and Suspicious records to train"
        }

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    return {
        "status": "success",
        "message": "Model trained successfully",
        "training_records": len(df),
        "accuracy": round(accuracy * 100, 2),
        "model_path": MODEL_PATH
    }