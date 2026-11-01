import glob, pandas as pd, joblib
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay

use = ["frame.time_epoch", "wlan.fc.type", "wlan.fc.subtype", "frame.len",
       "radiotap.dbm_antsignal", "wlan.fc.retry", "Label"]
files = sorted(glob.glob("Deauth_*.csv"), key=lambda f: int(f.split("_")[1].split(".")[0]))
df = pd.concat([pd.read_csv(f, usecols=use, low_memory=False) for f in files], ignore_index=True)

df["t"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
df = df.dropna(subset=["t"])
df["window"] = (df["t"] - df["t"].min()).astype(int)
df["is_deauth"] = ((df["wlan.fc.type"] == 0) & (df["wlan.fc.subtype"] == 12)).astype(int)
df["is_attack"] = (df["Label"] == "Deauth").astype(int)
df["sig"] = pd.to_numeric(df["radiotap.dbm_antsignal"].astype(str).str.extract(r"(-?\d+)")[0], errors="coerce")
df["retry"] = pd.to_numeric(df["wlan.fc.retry"], errors="coerce")

g = df.groupby("window")
feat = pd.DataFrame({
    "total_frames": g.size(),
    "deauth_frames": g["is_deauth"].sum(),
    "avg_signal": g["sig"].mean(),
    "avg_len": g["frame.len"].mean(),
    "retry_ratio": g["retry"].mean(),
    "label": g["is_attack"].max().astype(int),
})
feat["deauth_ratio"] = feat["deauth_frames"] / feat["total_frames"]
feat = feat.fillna(feat.median())
feat.to_csv("features_awid3.csv")
print("Windows:", len(feat))
print(feat["label"].value_counts())

FEATS = ["total_frames", "deauth_frames", "deauth_ratio", "avg_signal", "avg_len", "retry_ratio"]

m = joblib.load("wids_model.joblib")
p = m.predict(feat[FEATS])
print("\n=== Model on AWID3 (no retraining) ===")
print("Accuracy:", round(accuracy_score(feat["label"], p), 4))
print(confusion_matrix(feat["label"], p, labels=[0, 1]))
print(classification_report(feat["label"], p, labels=[0, 1], target_names=["normal", "attack"], zero_division=0))
wrong = feat.assign(pred=p)[feat["label"] != p]
print("Wrong windows:", len(wrong))
print(wrong[["total_frames", "deauth_frames", "label", "pred"]])

ConfusionMatrixDisplay(confusion_matrix(feat["label"], p), display_labels=["normal", "attack"]).plot()
plt.title("Unseen AWID3 test (no retraining)")
plt.savefig("AWID3_confusion_matrix.png", dpi=200)