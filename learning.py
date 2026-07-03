from collections import Counter
from datetime import datetime

LEARNING_LIMIT = 15

def get_login_hour(login_time):
    if isinstance(login_time, str):
        login_time = datetime.fromisoformat(login_time.replace("Z", ""))
    return login_time.hour

def update_user_behavior(cursor, user_id):
    cursor.execute("""
        SELECT device, browser, login_time, ip_address, session_hash
        FROM login_events
        WHERE user_id = %s AND status IN ('Learning', 'Normal')
        ORDER BY login_time ASC
    """, (user_id,))

    records = cursor.fetchall()

    if not records:
        return

    devices = [r["device"] for r in records]
    browsers = [r["browser"] for r in records]
    hours = [r["login_time"].hour for r in records]

    login_count = len(records)
    learning_status = "Detection" if login_count >= LEARNING_LIMIT else "Learning"

    preferred_device = Counter(devices).most_common(1)[0][0]
    preferred_browser = Counter(browsers).most_common(1)[0][0]
    average_login_hour = sum(hours) / len(hours)

    last_ip_address = records[-1]["ip_address"]
    last_session_hash = records[-1]["session_hash"]

    cursor.execute("""
        INSERT INTO user_behavior (
            user_id, login_count, learning_status,
            preferred_device, preferred_browser,
            average_login_hour, last_ip_address, last_session_hash
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
            login_count = VALUES(login_count),
            learning_status = VALUES(learning_status),
            preferred_device = VALUES(preferred_device),
            preferred_browser = VALUES(preferred_browser),
            average_login_hour = VALUES(average_login_hour),
            last_ip_address = VALUES(last_ip_address),
            last_session_hash = VALUES(last_session_hash)
    """, (
        user_id, login_count, learning_status,
        preferred_device, preferred_browser,
        average_login_hour, last_ip_address, last_session_hash
    ))

def calculate_risk(login_data, behavior):
    risk_score = 0
    reasons = []

    login_hour = get_login_hour(login_data["login_time"])

    if behavior["preferred_device"] and login_data["device"] != behavior["preferred_device"]:
        risk_score += 25
        reasons.append("New device detected")

    if behavior["preferred_browser"] and login_data["browser"] != behavior["preferred_browser"]:
        risk_score += 15
        reasons.append("New browser detected")

    if behavior["average_login_hour"] is not None:
        hour_difference = abs(login_hour - float(behavior["average_login_hour"]))
        if hour_difference > 5:
            risk_score += 20
            reasons.append("Unusual login time")

    if behavior["last_ip_address"] and login_data["ip_address"] != behavior["last_ip_address"]:
        risk_score += 20
        reasons.append("IP address changed")

    if behavior["last_session_hash"] and login_data["session_hash"] == behavior["last_session_hash"]:
        risk_score += 30
        reasons.append("Possible session reuse")

    if risk_score >= 70:
        return risk_score, "Suspicious", ", ".join(reasons), "Block Session"
    elif risk_score >= 40:
        return risk_score, "Suspicious", ", ".join(reasons), "Force Re-login"
    else:
        return risk_score, "Normal", "Normal login pattern", "Allow"