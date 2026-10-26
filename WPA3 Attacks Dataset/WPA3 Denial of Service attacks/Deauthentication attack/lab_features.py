import sys
from collections import defaultdict
import numpy as np, pandas as pd, joblib
from scapy.all import PcapReader
from scapy.layers.dot11 import Dot11, RadioTap

def build(path):
    rows = defaultdict(lambda: {"n": 0, "deauth": 0, "retry": 0, "len": 0, "sig": []})
    t0 = None
    for pkt in PcapReader(path):
        if not pkt.haslayer(Dot11):
            continue
        t = float(pkt.time)
        if t0 is None:
            t0 = t
        r = rows[int(t - t0)]
        d = pkt[Dot11]
        r["n"] += 1
        r["len"] += len(pkt)
        if d.FCfield & 0x8:
            r["retry"] += 1
        sig = getattr(pkt[RadioTap], "dBm_AntSignal", None) if pkt.haslayer(RadioTap) else None
        if sig is not None:
            r["sig"].append(sig)
        if d.type == 0 and d.subtype == 12:
            r["deauth"] += 1
    out = []
    for w in sorted(rows):
        r = rows[w]
        out.append({
            "window": w,
            "total_frames": r["n"],
            "deauth_frames": r["deauth"],
            "deauth_ratio": r["deauth"] / r["n"],
            "avg_signal": np.mean(r["sig"]) if r["sig"] else np.nan,
            "avg_len": r["len"] / r["n"],
            "retry_ratio": r["retry"] / r["n"],
        })
    return pd.DataFrame(out)

normal = build(sys.argv[1])
normal["label"] = 0
normal["file"] = "normal"

attack = build(sys.argv[2])
dw = attack.loc[attack["deauth_frames"] > 0, "window"]
attack["label"] = ((attack["window"] >= dw.min()) & (attack["window"] <= dw.max())).astype(int)
attack["file"] = "attack"

print("normal.pcap seconds:", len(normal), "| deauth frames:", int(normal["deauth_frames"].sum()))
print("attack.pcap seconds:", len(attack), "| attack seconds:", int(attack["label"].sum()),
      "| range:", dw.min(), "to", dw.max())

lab = pd.concat([normal, attack], ignore_index=True)
print("avg_signal values:", lab["avg_signal"].round(1).unique()[:10])
lab["avg_signal"] = lab["avg_signal"].fillna(-30)
lab.to_csv("features_lab.csv", index=False)

# Transfer test: model trained on the Mendeley data, tested on your lab data
from sklearn.metrics import accuracy_score, confusion_matrix
FEATS = ["total_frames", "deauth_frames", "deauth_ratio", "avg_signal", "avg_len", "retry_ratio"]
model = joblib.load("wids_model.joblib")
pred = model.predict(lab[FEATS])
print("\nOld model on lab data, accuracy:", accuracy_score(lab["label"], pred))
print(confusion_matrix(lab["label"], pred))