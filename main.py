"""
Improved NextGen IDS prototype (single-file)
--------------------------------------------
Features:
- Flow-based feature extraction (windowed stats, entropy, inter-arrival)
- IsolationForest anomaly scoring (unsupervised)
- SGDClassifier supervised model with online feedback
- IOC enrichment (IPs/domains)
- Flask API to:
    - View alerts (/alerts)
    - Label alerts (/label)
    - Adjust thresholds (/set_threshold)
    - Status (/status)
    - Test alerts without sniffing (/test_alert)

Run:
    pip install -r requirements.txt
    python improved_main.py

Notes:
- For packet capture: Run as admin/root and install Npcap (Windows) or libpcap (Linux).
- Without privileges, API still runs; you can use /test_alert to simulate.
"""

import time, threading, json, os, math, logging
from collections import defaultdict, deque
from typing import Dict, Any, Tuple
import yaml
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from joblib import dump, load
from flask import Flask, request, jsonify

# Networking
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# -------------------------
# Logging
# -------------------------
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nextgen-ids")

# -------------------------
# Config
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
# Utility
# -------------------------
def entropy_bytes(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    probs = [c / len(b) for c in counts if c > 0]
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
                    self.ip_set |= {l.strip() for l in f if l.strip()}
            except FileNotFoundError:
                pass
        for path in self.cfg.get("ioc_domain_files", []):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.dom_set |= {l.strip().lower() for l in f if l.strip()}
            except FileNotFoundError:
                pass

    def score(self, src, dst, sni=None):
        score, hits = 0.0, []
        if src in self.ip_set:
            score += 0.6; hits.append(("src_ip_ioc", src))
        if dst in self.ip_set:
            score += 0.6; hits.append(("dst_ip_ioc", dst))
        if sni:
            sni_l = sni.lower()
            for d in self.dom_set:
                if d in sni_l:
                    score += 0.6; hits.append(("sni_domain_ioc", d))
        return min(score, 1.0), hits

intel = Intel(CFG.get("intel", {}))

# -------------------------
# Flow rollup
# -------------------------
FlowKey = Tuple[str, int, str, int, str]

class FlowRollup:
    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.store = defaultdict(deque)

    def add_packet(self, key: FlowKey, pkt_len: int, ts: float, payload: bytes=b""):
        dq = self.store[key]
        dq.append((ts, pkt_len, payload))
        cutoff = ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def summarize(self, key: FlowKey):
        dq = self.store.get(key)
        if not dq: return None
        n = len(dq)
        bytes_sum = sum(x[1] for x in dq)
        durations = dq[-1][0] - dq[0][0] if n > 1 else 0.0001
        avg_len = bytes_sum / n
        inter_arrivals = [dq[i][0]-dq[i-1][0] for i in range(1, n)]
        iat_mean = float(np.mean(inter_arrivals)) if inter_arrivals else 0.0
        payload_concat = b"".join(x[2] for x in dq if x[2])
        ent = entropy_bytes(payload_concat)
        unique_dports = len({k[3] for k in self.store.keys()})
        return {
            "samples": n, "bytes": bytes_sum, "packets": n, "duration": durations,
            "avg_len": avg_len, "iat_mean": iat_mean, "entropy": ent,
            "unique_dports": unique_dports
        }

flowroll = FlowRollup(window_seconds=CFG["features"]["window_seconds"])

# -------------------------
# ML engines
# -------------------------
class UnsupervisedEngine:
    def __init__(self, contamination=0.01):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.buffer, self.warmed = [], False

    def _vec(self, f: Dict[str, Any]):
        return np.array([
            f.get("samples",0), f.get("bytes",0), f.get("packets",0),
            f.get("duration",0.0001), f.get("avg_len",0), f.get("iat_mean",0),
            f.get("entropy",0), f.get("unique_dports",0)
        ], float)

    def partial_fit_buffer(self, f, min_samples=200):
        v = self._vec(f)
        self.buffer.append(v)
        if not self.warmed and len(self.buffer) >= min_samples:
            X = np.vstack(self.buffer)
            self.scaler.fit(X); self.model.fit(self.scaler.transform(X))
            self.warmed, self.buffer = True, []

    def score(self, f: Dict[str, Any]):
        if not self.warmed: return 0.0
        v = self.scaler.transform(self._vec(f).reshape(1,-1))
        raw = self.model.decision_function(v)[0]
        return float(1.0 / (1.0 + math.exp(5*raw)))

unsuper = UnsupervisedEngine(CFG["anomaly"]["contamination"])

class SupervisedEngine:
    def __init__(self, enabled=True, model_path="supervised.joblib"):
        self.enabled, self.model_path = enabled, model_path
        self.scaler = StandardScaler()
        if enabled: self._init_model()

    def _init_model(self):
        self.model = SGDClassifier(max_iter=1000, tol=1e-3)
        X0 = np.zeros((2,8)); y0 = np.array([0,1])
        self.scaler.fit(X0); self.model.partial_fit(self.scaler.transform(X0), y0, classes=[0,1])
        if os.path.exists(self.model_path):
            try:
                saved = load(self.model_path)
                self.model, self.scaler = saved["model"], saved["scaler"]
            except Exception: pass

    def _vec(self, f: Dict[str,Any]):
        return np.array([
            f.get("samples",0), f.get("bytes",0), f.get("packets",0),
            f.get("duration",0.0001), f.get("avg_len",0), f.get("iat_mean",0),
            f.get("entropy",0), f.get("unique_dports",0)
        ], float)

    def predict_proba(self, f: Dict[str,Any]):
        if not self.enabled: return 0.0
        try:
            score = self.model.decision_function(self.scaler.transform(self._vec(f).reshape(1,-1)))[0]
            return float(1.0/(1.0+math.exp(-score)))
        except: return 0.0

    def partial_fit_label(self, f: Dict[str,Any], label:int):
        v = self._vec(f).reshape(1,-1)
        self.scaler.partial_fit(v) if hasattr(self.scaler,"partial_fit") else self.scaler.fit(v)
        self.model.partial_fit(self.scaler.transform(v), [label])
        dump({"model": self.model, "scaler": self.scaler}, self.model_path)

supervised = SupervisedEngine(CFG["supervised"]["enabled"], CFG["supervised"]["model_path"])

# -------------------------
# Alerts
# -------------------------
ALERTS, ALERT_SEQ = {}, 0
LABELS_FILE = CFG["persistence"]["labels_file"]

def persist_label(alert_id, label):
    with open(LABELS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{alert_id},{label},{int(time.time())}\n")

# -------------------------
# Pipeline
# -------------------------
def handle_packet(pkt):
    global ALERT_SEQ
    if not pkt.haslayer(IP): return
    ts, ip = time.time(), pkt[IP]
    proto, sport, dport = "other",0,0
    if pkt.haslayer(TCP): proto,sport,dport="tcp",pkt[TCP].sport,pkt[TCP].dport
    elif pkt.haslayer(UDP): proto,sport,dport="udp",pkt[UDP].sport,pkt[UDP].dport
    key=(ip.src,sport,ip.dst,dport,proto)
    payload=bytes(pkt.payload) if pkt.payload else b""
    flowroll.add_packet(key,len(pkt),ts,payload)
    summary=flowroll.summarize(key)
    if not summary: return
    unsuper.partial_fit_buffer(summary)
    us, sp, intel_score, hits = unsuper.score(summary), supervised.predict_proba(summary), *intel.score(ip.src,ip.dst)
    risk=min(1.0,0.6*us+0.3*sp+0.8*intel_score)
    ALERT_SEQ+=1; alert_id=f"A{int(ts)}-{ALERT_SEQ}"
    alert={"id":alert_id,"ts":ts,"src":ip.src,"dst":ip.dst,"proto":proto,"features":summary,
           "scores":{"unsup":us,"sup":sp,"intel":intel_score},"intel_hits":hits,"risk":risk}
    ALERTS[alert_id]=alert
    if risk>=CFG["anomaly"]["score_threshold"]:
        logger.warning("🚨 ALERT %s risk=%.2f", alert_id, risk)

# -------------------------
# Sniffer thread
# -------------------------
def start_sniffer():
    if not SCAPY_AVAILABLE:
        logger.error("Scapy not available, skipping packet capture.")
        return
    try:
        iface=CFG["capture"]["iface"]; bpf=CFG["capture"]["bpf"]
        logger.info("[sniffer] starting iface=%s bpf=%s", iface,bpf)
        sniff(iface=iface,filter=bpf,prn=handle_packet,store=False)
    except Exception as e:
        logger.error("Sniffer failed: %s", e)

# -------------------------
# Flask API
# -------------------------
app=Flask("improved-ids")

@app.get("/alerts")
def get_alerts():
    return jsonify({"alerts":sorted(ALERTS.values(),key=lambda x:x["ts"],reverse=True)})

@app.post("/label")
def label_alert():
    d=request.json; aid,lab=d.get("id"),int(d.get("label",0))
    if aid not in ALERTS: return jsonify({"error":"unknown alert"}),404
    supervised.partial_fit_label(ALERTS[aid]["features"],lab)
    persist_label(aid,lab)
    return jsonify({"status":"ok","id":aid,"label":lab})

@app.post("/set_threshold")
def set_threshold():
    thr=float(request.json.get("threshold",CFG["anomaly"]["score_threshold"]))
    CFG["anomaly"]["score_threshold"]=thr
    with open(CFG_PATH,"w",encoding="utf-8") as f: yaml.safe_dump(CFG,f)
    return jsonify({"status":"ok","threshold":thr})

@app.get("/status")
def status():
    return jsonify({"alerts":len(ALERTS),"unsup_warmed":unsuper.warmed,
                    "sup_enabled":supervised.enabled,"threshold":CFG["anomaly"]["score_threshold"]})

@app.post("/test_alert")
def test_alert():
    """simulate an alert without sniffing"""
    fake={"samples":5,"bytes":200,"packets":5,"duration":1,"avg_len":40,"iat_mean":0.2,"entropy":3.5,"unique_dports":1}
    us, sp, intel_score, hits = unsuper.score(fake), supervised.predict_proba(fake), *intel.score("1.2.3.4","5.6.7.8")
    risk=min(1.0,0.6*us+0.3*sp+0.8*intel_score)
    aid=f"T{int(time.time())}"
    alert={"id":aid,"ts":time.time(),"src":"1.2.3.4","dst":"5.6.7.8","proto":"tcp","features":fake,
           "scores":{"unsup":us,"sup":sp,"intel":intel_score},"intel_hits":hits,"risk":risk}
    ALERTS[aid]=alert
    return jsonify(alert)

# -------------------------
# Main
# -------------------------
if __name__=="__main__":
    threading.Thread(target=start_sniffer,daemon=True).start()
    app.run(host=CFG["api"]["host"],port=CFG["api"]["port"])
