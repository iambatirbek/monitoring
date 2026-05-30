from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import random
import threading
import time
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-monitor-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# --- AI anomaliya aniqlash modeli (simulyatsiya) ---
class AIAnomalyDetector:
    def __init__(self):
        self.threshold = 5000
        self.history = []

    def analyze(self, packet_count, protocol, source_ip):
        risk = 0
        reason = "Normal"

        if packet_count > self.threshold:
            risk += 60
            reason = "DDoS hujumi"
        if protocol == "UNKNOWN":
            risk += 30
            reason = "Noma'lum protokol"
        if source_ip.startswith("45.") or source_ip.startswith("91."):
            risk += 40
            reason = "Shubhali IP manzil"
        if packet_count > 2000 and protocol == "TCP":
            risk += 20
            reason = "Port skanerlash"

        risk = min(risk, 100)
        level = "critical" if risk > 70 else "warning" if risk > 30 else "info"
        return {"risk": risk, "reason": reason, "level": level}

detector = AIAnomalyDetector()

# --- Ma'lumotlar ---
stats = {
    "packets_per_sec": 4821,
    "anomalies": 0,
    "blocked_ips": 143,
    "latency_ms": 14,
    "security_score": 92,
    "alerts": [],
    "traffic_history": [random.randint(2000, 6000) for _ in range(60)],
    "suspicious_history": [random.randint(0, 400) for _ in range(60)],
}

ATTACK_SCENARIOS = [
    {"ip": "45.33.32.156", "protocol": "TCP", "type": "Port skanerlash", "packets": 3200},
    {"ip": "192.168.1.45", "protocol": "UDP", "type": "DDoS hujumi", "packets": 8500},
    {"ip": "103.21.244.0", "protocol": "SSH", "type": "Brute-force", "packets": 1800},
    {"ip": "185.220.101.1", "protocol": "HTTP", "type": "Fishing", "packets": 950},
    {"ip": "91.108.4.1", "protocol": "UNKNOWN", "type": "Noma'lum hujum", "packets": 4100},
]

def generate_traffic():
    while True:
        normal = random.randint(2500, 6500)
        suspicious = random.randint(0, 600)

        stats["packets_per_sec"] = normal + suspicious
        stats["latency_ms"] = random.randint(8, 35)
        stats["traffic_history"].append(normal)
        stats["traffic_history"] = stats["traffic_history"][-60:]
        stats["suspicious_history"].append(suspicious)
        stats["suspicious_history"] = stats["suspicious_history"][-60:]

        # Tasodifiy hujum simulyatsiyasi (har 20 sekundda)
        if random.random() < 0.05:
            scenario = random.choice(ATTACK_SCENARIOS)
            result = detector.analyze(
                scenario["packets"], scenario["protocol"], scenario["ip"]
            )
            alert = {
                "id": int(time.time() * 1000),
                "type": result["level"],
                "title": scenario["type"],
                "meta": f"{scenario['ip']} · {scenario['packets']} paket/s",
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "risk": result["risk"],
            }
            stats["alerts"].insert(0, alert)
            stats["alerts"] = stats["alerts"][:10]
            stats["anomalies"] += 1
            stats["blocked_ips"] += 1
            stats["security_score"] = max(50, stats["security_score"] - random.randint(2, 8))
        else:
            stats["security_score"] = min(99, stats["security_score"] + 1)

        socketio.emit("update", {
            "packets_per_sec": stats["packets_per_sec"],
            "anomalies": stats["anomalies"],
            "blocked_ips": stats["blocked_ips"],
            "latency_ms": stats["latency_ms"],
            "security_score": stats["security_score"],
            "traffic_history": stats["traffic_history"],
            "suspicious_history": stats["suspicious_history"],
            "alerts": stats["alerts"][:5],
        })

        time.sleep(2)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def get_stats():
    return jsonify(stats)

@app.route("/api/simulate-attack")
def simulate_attack():
    scenario = random.choice(ATTACK_SCENARIOS)
    result = detector.analyze(scenario["packets"], scenario["protocol"], scenario["ip"])
    alert = {
        "id": int(time.time() * 1000),
        "type": result["level"],
        "title": scenario["type"],
        "meta": f"{scenario['ip']} · {scenario['packets']} paket/s",
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "risk": result["risk"],
    }
    stats["alerts"].insert(0, alert)
    stats["alerts"] = stats["alerts"][:10]
    stats["anomalies"] += 1
    stats["blocked_ips"] += 1
    stats["security_score"] = max(50, stats["security_score"] - random.randint(5, 15))
    return jsonify({"status": "ok", "alert": alert})

@app.route("/api/clear")
def clear_alerts():
    stats["alerts"] = []
    stats["anomalies"] = 0
    stats["security_score"] = 97
    return jsonify({"status": "ok"})

@socketio.on("connect")
def on_connect():
    emit("update", stats)

if __name__ == "__main__":
    thread = threading.Thread(target=generate_traffic, daemon=True)
    thread.start()
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
