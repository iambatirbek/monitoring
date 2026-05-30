from flask import Flask, render_template, jsonify
import random
import threading
import time
import datetime

app = Flask(__name__)

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

        if random.random() < 0.05:
            scenario = random.choice(ATTACK_SCENARIOS)
            risk = 80 if scenario["packets"] > 5000 else 50
            level = "critical" if risk > 70 else "warning"
            alert = {
                "id": int(time.time() * 1000),
                "type": level,
                "title": scenario["type"],
                "meta": f"{scenario['ip']} · {scenario['packets']} paket/s",
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "risk": risk,
            }
            stats["alerts"].insert(0, alert)
            stats["alerts"] = stats["alerts"][:10]
            stats["anomalies"] += 1
            stats["blocked_ips"] += 1
            stats["security_score"] = max(50, stats["security_score"] - random.randint(2, 8))
        else:
            stats["security_score"] = min(99, stats["security_score"] + 1)

        time.sleep(2)

thread = threading.Thread(target=generate_traffic, daemon=True)
thread.start()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def get_stats():
    return jsonify(stats)

@app.route("/api/simulate-attack")
def simulate_attack():
    scenario = random.choice(ATTACK_SCENARIOS)
    alert = {
        "id": int(time.time() * 1000),
        "type": "critical",
        "title": scenario["type"],
        "meta": f"{scenario['ip']} · {scenario['packets']} paket/s",
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "risk": 85,
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
