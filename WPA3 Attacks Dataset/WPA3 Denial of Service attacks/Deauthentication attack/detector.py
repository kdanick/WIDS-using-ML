import sys, time, argparse
from collections import Counter
import joblib, pandas as pd
from scapy.all import PcapReader
from scapy.layers.dot11 import Dot11, RadioTap

ap = argparse.ArgumentParser()
ap.add_argument("pcap")
ap.add_argument("--start", type=int, default=0, help="start second")
ap.add_argument("--seconds", type=int, default=60, help="how many seconds to process")
ap.add_argument("--live", action="store_true", help="wait 1s per window")
args = ap.parse_args()

model = joblib.load("wids_model.joblib")
FEATS = ["total_frames", "deauth_frames", "deauth_ratio", "avg_len", "retry_ratio"]
blocked = set()

def classify(sec, total, deauth, sigs, lens, retries, senders):
    f = pd.DataFrame([{
        "total_frames": total,
        "deauth_frames": deauth,
        "deauth_ratio": deauth / total,
        "avg_signal": sum(sigs) / len(sigs) if sigs else -60,
        "avg_len": sum(lens) / len(lens),
        "retry_ratio": retries / total,
    }])[FEATS]
    if model.predict(f)[0] == 1:
        mac, count = senders.most_common(1)[0] if senders else ("unknown", 0)
        print(f"[ALERT] t={sec}s deauth flood: {deauth} deauth frames, top sender {mac}")
        if mac not in blocked:
            blocked.add(mac)
            with open("blocklist.log", "a") as log:
                log.write(f"{time.ctime()} t={sec}s blocked {mac} ({count} deauth frames)\n")
            print(f"[WIPS] logged {mac} to blocklist.log")
    else:
        print(f"t={sec}s normal ({total} frames)")
    if args.live:
        time.sleep(1)

t0, cur = None, None
total = deauth = retries = 0
sigs, lens, senders = [], [], Counter()

for pkt in PcapReader(args.pcap):
    if not pkt.haslayer(Dot11):
        continue
    t = float(pkt.time)
    if t0 is None:
        t0 = t
    sec = int(t - t0)
    if sec < args.start:
        continue
    if sec >= args.start + args.seconds:
        break
    if cur is None:
        cur = sec
    if sec != cur:
        if total:
            classify(cur, total, deauth, sigs, lens, retries, senders)
        cur = sec
        total = deauth = retries = 0
        sigs, lens, senders = [], [], Counter()
    d = pkt[Dot11]
    total += 1
    lens.append(len(pkt))
    if d.FCfield & 0x8:
        retries += 1
    if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal") and pkt[RadioTap].dBm_AntSignal is not None:
        sigs.append(pkt[RadioTap].dBm_AntSignal)
    if d.type == 0 and d.subtype == 12:
        deauth += 1
        senders[d.addr2] += 1

if total:
    classify(cur, total, deauth, sigs, lens, retries, senders)