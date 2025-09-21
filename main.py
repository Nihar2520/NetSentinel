"""
Improved NextGen IDS prototype (single-file):
- richer features (flow rollup, inter-arrival, counts)
- IsolationForest anomaly scoring (unsupervised)
- SGDClassifier incremental supervised model (optional)
- IOC enrichment from local files
- Feedback endpoint to label alerts and online-train supervised model
- Flask API to view alerts, label them, change thresholds
Run:
    pip install -r requirements.txt
    python improved_main.py
Notes:
- Run as admin/root for packet capture.
- For Windows, install Npcap.
"""

import time
import threading
import json
import os
from collections import defaultdict, deque
from typing import Dict, Any, Tuple, List
import yaml
import math

# networking / sniffing
from scapy.all import sniff, IP, TCP, UDP  # requires Npcap on Windows

# ML
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from joblib import dump, load

# web API
from flask import Flask, request, jsonify

# -------------------------
# Config & persistence
# -------------------------
CFG_PATH = "config.yaml"
DEFAULT_CFG = {
    "capture": {"iface": None, "bpf": "ip", "batch_seconds": 2},
    "features": {"window_seconds": 60},
    "anomaly": {"contamination": 0.01, "score_threshold": 0.7},
    "supervised": {"enabled": True, "model_path": "supervised.joblib"},
    "intel": {"ioc_ip_files": [], "ioc_domain_files": []},
    "persistence": {"labels_file": "labels.csv", "model_dir": "."},
    "api": {"host": "0.0.0.0", "port": 8000}
}

if not os.path.exists(CFG_PATH):
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(DEFAULT_CFG, f)

with open(CFG_PATH, "r", encoding="utf-8") as f:
    CFG = yaml.safe_load(f)

# -------------------------
# Utilities
# -------------------------
def entropy_bytes(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    probs = [c / len(b) for c in counts if c > 0]
    # Shannon entropy
    return -sum(p * math.log2(p) for p in probs)

# -------------------------
# IOC enrichment
# -------------------------
class Intel:
    def __init__(self, cfg):
        self.ip_set = set()
        self.dom_set = set()
        self.cfg = cfg
        self.load_files()

    def load_files(self):
        for path in self.cfg.get("ioc_ip_files", []):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for l in f:
                        s = l.strip()
                        if s:
                            self.ip_set.add(s)
            except FileNotFoundError:
                pass
        for path in self.cfg.get("ioc_domain_files", []):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for l in f:
                        s = l.strip().lower()
                        if s:
                            self.dom_set.add(s)
            except FileNotFoundError:
                pass

    def score(self, src, dst, sni=None):
        score = 0.0
        hits = []
        if src in self.ip_set:
            score += 0.6
            hits.append(("src_ip_ioc", src))
        if dst in self.ip_set:
            score += 0.6
            hits.append(("dst_ip_ioc", dst))
        if sni:
            sni_l = sni.lower()
            for d in self.dom_set:
                if d in sni_l:
                    score += 0.6
                    hits.append(("sni_domain_ioc", d))
        return min(score, 1.0), hits

intel = Intel(CFG.get("intel", {}))

# -------------------------
# Feature Rollup (flow/window)
# -------------------------
FlowKey = Tuple[str, int, str, int, str]

class FlowRollup:
    """
    Maintain per-flow windowed features. Features aggregated across a rolling window.
    """
    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self.store: Dict[FlowKey, deque] = defaultdict(deque)
        self.last_ts = time.time()

    def add_packet(self, key: FlowKey, pkt_len: int, ts: float, payload: bytes = b""):
        dq = self.store[key]
        dq.append((ts, pkt_len, payload))
        cutoff = ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def summarize(self, key: FlowKey):
        dq = self.store.get(key)
        if not dq:
            return None
        n = len(dq)
        bytes_sum = sum(x[1] for x in dq)
        durations = dq[-1][0] - dq[0][0] if n > 1 else 0.0001
        pkts = n
        avg_len = bytes_sum / n
        inter_arrivals = []
        prev = None
        for t, _, _ in dq:
            if prev is not None:
                inter_arrivals.append(t - prev)
            prev = t
        iat_mean = float(np.mean(inter_arrivals)) if inter_arrivals else 0.0
        payload_concat = b"".join(x[2] for x in dq if x[2])
        ent = entropy_bytes(payload_concat)
        unique_dports = len({k[3] for k in self.store.keys()})
        # Build feature dict
        features = {
            "samples": n,
            "bytes": bytes_sum,
            "packets": pkts,
            "duration": durations,
            "avg_len": avg_len,
            "iat_mean": iat_mean,
            "entropy": ent,
            "unique_dports": unique_dports
        }
        return features

flowroll = FlowRollup(window_seconds=CFG.get("features", {}).get("window_seconds", 60))

# -------------------------
# Unsupervised model
# -------------------------
class UnsupervisedEngine:
    def __init__(self, contamination=0.01):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.buffer = []
        self.warmed = False

    def _vec(self, features: Dict[str, Any]):
        return np.array([
            features.get("samples", 0),
            features.get("bytes", 0),
            features.get("packets", 0),
            features.get("duration", 0.0001),
            features.get("avg_len", 0.0),
            features.get("iat_mean", 0.0),
            features.get("entropy", 0.0),
            features.get("unique_dports", 0),
        ], dtype=float)

    def partial_fit_buffer(self, features: Dict[str, Any], min_samples=200):
        v = self._vec(features)
        self.buffer.append(v)
        if not self.warmed and len(self.buffer) >= min_samples:
            X = np.vstack(self.buffer)
            self.scaler.fit(X)
            Xs = self.scaler.transform(X)
            self.model.fit(Xs)
            self.warmed = True
            self.buffer = []

    def score(self, features: Dict[str, Any]):
        v = self._vec(features)
        if not self.warmed:
            return 0.0  # neutral during warm-up
        vs = self.scaler.transform(v.reshape(1, -1))
        raw = self.model.decision_function(vs)[0]  # higher -> more normal
        # map to 0..1 anomaly score (higher = more anomalous)
        score = 1.0 / (1.0 + math.exp(5 * raw))
        return float(score)

unsuper = UnsupervisedEngine(contamination=CFG.get("anomaly", {}).get("contamination", 0.01))

# -------------------------
# Supervised incremental model (SGD)
# -------------------------
class SupervisedEngine:
    def __init__(self, enabled=True, model_path="supervised.joblib"):
        self.enabled = enabled
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self._init_model()

    def _init_model(self):
        if not self.enabled:
            return
        # SGD requires partial_fit with class labels available
        # We'll start with a tiny initializer
        self.model = SGDClassifier(max_iter=1000, tol=1e-3)
        # We need to 'warm' the model with an initial partial_fit call
        # We'll create a fake small dataset to initialize classes [0,1]
        X0 = np.zeros((2,8))
        y0 = np.array([0,1])
        self.scaler.fit(X0)
        Xs = self.scaler.transform(X0)
        try:
            self.model.partial_fit(Xs, y0, classes=np.array([0,1]))
        except Exception:
            pass
        # If a saved model exists, load it
        if os.path.exists(self.model_path):
            try:
                loaded = load(self.model_path)
                self.model = loaded.get("model", self.model)
                self.scaler = loaded.get("scaler", self.scaler)
            except Exception:
                pass

    def _vec(self, features: Dict[str, Any]):
        return np.array([
            features.get("samples", 0),
            features.get("bytes", 0),
            features.get("packets", 0),
            features.get("duration", 0.0001),
            features.get("avg_len", 0.0),
            features.get("iat_mean", 0.0),
            features.get("entropy", 0.0),
            features.get("unique_dports", 0),
        ], dtype=float)

    def predict_proba(self, features: Dict[str, Any]) -> float:
        if not self.enabled or self.model is None:
            return 0.0
        v = self._vec(features).reshape(1, -1)
        vs = self.scaler.transform(v)
        # Use decision_function as proxy for probability
        try:
            score = self.model.decision_function(vs)[0]
            # map to 0..1
            prob = 1.0 / (1.0 + math.exp(-score))
            return float(prob)
        except Exception:
            return 0.0

    def partial_fit_label(self, features: Dict[str, Any], label: int):
        if not self.enabled or self.model is None:
            return
        v = self._vec(features).reshape(1, -1)
        # update scaler incrementally: naive approach - refit on small buffer isn't ideal, but acceptable here
        # For production - use an online scaler like River or keep a rolling buffer.
        self.scaler.partial_fit(v) if hasattr(self.scaler, "partial_fit") else self.scaler.fit(v)
        vs = self.scaler.transform(v)
        try:
            self.model.partial_fit(vs, np.array([label]))
        except Exception:
            # If model not yet compatible, try re-init
            pass
        # persist model occasionally
        try:
            dump({"model": self.model, "scaler": self.scaler}, self.model_path)
        except Exception:
            pass

supervised = SupervisedEngine(enabled=CFG.get("supervised", {}).get("enabled", True),
                              model_path=CFG.get("supervised", {}).get("model_path", "supervised.joblib"))

# -------------------------
# Alerts store + IDs
# -------------------------
ALERTS: Dict[str, Dict[str, Any]] = {}
ALERT_SEQ = 0
LABELS_FILE = CFG.get("persistence", {}).get("labels_file", "labels.csv")

def persist_label(alert_id: str, label: int):
    # append label for later offline training
    try:
        with open(LABELS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{alert_id},{label},{int(time.time())}\n")
    except Exception:
        pass

# -------------------------
# Packet handler & pipeline
# -------------------------
def make_flow_key(pkt) -> FlowKey:
    ip = pkt.getlayer(IP)
    proto = "other"
    sport = 0
    dport = 0
    if pkt.haslayer(TCP):
        proto = "tcp"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        proto = "udp"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    return (ip.src, sport, ip.dst, dport, proto)

def handle_packet(pkt):
    global ALERT_SEQ
    ts = time.time()
    if not pkt.haslayer(IP):
        return
    key = make_flow_key(pkt)
    payload = bytes(pkt.payload) if pkt.payload else b""
    flowroll.add_packet(key, len(pkt), ts, payload)
    summary = flowroll.summarize(key)
    if not summary:
        return
    # unsupervised warm-up
    unsuper.partial_fit_buffer(summary, min_samples=200)
    unsup_score = unsuper.score(summary)
    sup_score = supervised.predict_proba(summary) if supervised.enabled else 0.0
    intel_score, intel_hits = intel.score(key[0], key[2])

    # ensemble risk score: weighted
    risk = min(1.0, 0.6 * unsup_score + 0.3 * sup_score + 0.8 * intel_score)

    ALERT_SEQ += 1
    alert_id = f"A{int(time.time())}-{ALERT_SEQ}"
    alert = {
        "id": alert_id,
        "ts": ts,
        "src": key[0],
        "sport": key[1],
        "dst": key[2],
        "dport": key[3],
        "proto": key[4],
        "features": summary,
        "scores": {"unsupervised": unsup_score, "supervised": sup_score, "intel": intel_score},
        "intel_hits": intel_hits,
        "risk": risk
    }

    # decide to raise alert based on config threshold
    threshold = CFG.get("anomaly", {}).get("score_threshold", 0.7)
    if risk >= threshold:
        ALERTS[alert_id] = alert
        print(f"🚨 ALERT {alert_id} risk={risk:.3f} unsup={unsup_score:.3f} sup={sup_score:.3f} intel={intel_score:.3f}")
        # NOTE: here you can call integration.siem.send_alert(alert) to forward to Wazuh
        # To keep the prototype self-contained we only print; user can enable forwarding.
    else:
        # not raised; but we still store low-risk sample for diagnostics
        ALERTS[alert_id] = alert

# -------------------------
# Sniffer thread
# -------------------------
def start_sniffer():
    iface = CFG.get("capture", {}).get("iface", None)
    bpf = CFG.get("capture", {}).get("bpf", "ip")
    print(f"[sniffer] starting on iface={iface} bpf='{bpf}' (requires privileges)")
    sniff(iface=iface, filter=bpf, prn=handle_packet, store=False)

# -------------------------
# Flask API
# -------------------------
app = Flask("improved-ids")

@app.get("/alerts")
def get_alerts():
    # return all alerts sorted by ts desc
    arr = sorted(ALERTS.values(), key=lambda x: x["ts"], reverse=True)
    return jsonify({"count": len(arr), "alerts": arr})

@app.post("/label")
def label_alert():
    """
    Label an alert as true(1) or false(0).
    Body: {"id": "<alert_id>", "label": 1}
    This will call supervised.partial_fit_label(...) to incrementally train.
    """
    data = request.json
    if not data:
        return jsonify({"error": "no json body"}), 400
    aid = data.get("id")
    lab = int(data.get("label", 0))
    if aid not in ALERTS:
        return jsonify({"error": "unknown alert id"}), 404
    # get features and online-train supervised model
    features = ALERTS[aid]["features"]
    supervised.partial_fit_label(features, lab)
    persist_label(aid, lab)
    return jsonify({"status": "ok", "id": aid, "label": lab})

@app.post("/set_threshold")
def set_threshold():
    data = request.json
    if not data:
        return jsonify({"error":"no body"}), 400
    thr = float(data.get("threshold", CFG.get("anomaly", {}).get("score_threshold", 0.7)))
    CFG["anomaly"]["score_threshold"] = thr
    # persist config
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(CFG, f)
    return jsonify({"status":"ok", "threshold": thr})

@app.get("/status")
def status():
    return jsonify({
        "alerts_stored": len(ALERTS),
        "unsuper_warmed": unsuper.warmed,
        "supervised_enabled": supervised.enabled,
        "threshold": CFG.get("anomaly", {}).get("score_threshold", 0.7)
    })

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    # start sniffer in background thread
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()
    # run api (main thread)
    app.run(host=CFG.get("api", {}).get("host", "0.0.0.0"),
            port=CFG.get("api", {}).get("port", 8000))
