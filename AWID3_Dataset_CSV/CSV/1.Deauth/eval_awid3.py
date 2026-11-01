import glob, pandas as pd, joblib
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay

# Save a labeled confusion-matrix plot with accuracy and interpretation notes.
def save_cm(y_true, y_pred, title, subtitle, filename):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    acc = accuracy_score(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(8, 6.5))
    ConfusionMatrixDisplay(cm, display_labels=["Normal traffic", "Deauth attack"]).plot(
        ax=ax, values_format="d")
    ax.set_xlabel("What the model predicted")
    ax.set_ylabel("What actually happened")
    ax.set_title(f"{title}\n{subtitle}\nAccuracy: {acc:.1%}", fontsize=11)
    fig.text(0.5, 0.03,
             "Each number = count of 1-second windows of Wi-Fi traffic.\n"
             "Top-left and bottom-right = correct. Top-right = false alarms. Bottom-left = missed attacks.",
             ha="center", fontsize=9)
    fig.subplots_adjust(bottom=0.2, top=0.82)
    fig.savefig(filename, dpi=200)
    plt.close(fig)

# 1. Load all AWID3 deauth files in order
use = ["frame.time_epoch", "wlan.fc.type", "wlan.fc.subtype", "frame.len",
       "radiotap.dbm_antsignal", "wlan.fc.retry", "Label"]
files = sorted(glob.glob("Deauth_*.csv"), key=lambda f: int(f.split("_")[1].split(".")[0]))
df = pd.concat([pd.read_csv(f, usecols=use, low_memory=False) for f in files], ignore_index=True)

# 2. Per-frame helpers and 1-second windows
df["t"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
df = df.dropna(subset=["t"])
df["window"] = (df["t"] - df["t"].min()).astype(int)
df["is_deauth"] = ((df["wlan.fc.type"] == 0) & (df["wlan.fc.subtype"] == 12)).astype(int)
df["is_attack"] = (df["Label"] == "Deauth").astype(int)
df["sig"] = pd.to_numeric(df["radiotap.dbm_antsignal"].astype(str).str.extract(r"(-?\d+)")[0], errors="coerce")
df["retry"] = pd.to_numeric(df["wlan.fc.retry"], errors="coerce")

# 3. Same features as train.py: one row per second
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

# 4. Evaluate the saved model on AWID3 without retraining it
FEATS = ["total_frames", "deauth_frames", "deauth_ratio", "avg_signal", "avg_len", "retry_ratio"]
m = joblib.load("wids_model.joblib")
p = m.predict(feat[FEATS])
print("\n=== Model on AWID3 (no retraining) ===")
print("Accuracy:", round(accuracy_score(feat["label"], p), 4))
print(confusion_matrix(feat["label"], p, labels=[0, 1]))
print(classification_report(feat["label"], p, labels=[0, 1], target_names=["normal", "attack"], zero_division=0))
# Inspect the windows where the model's prediction differs from the known label.
wrong = feat.assign(pred=p)[feat["label"] != p]
print("Wrong windows:", len(wrong))
print(wrong[["total_frames", "deauth_frames", "label", "pred"]])

save_cm(feat["label"], p,
        "Same Random Forest detector, tested on a different network",
        f"AWID3 dataset: {len(feat)} seconds never seen in training, no retraining",
        "CM_AWID3_test.png")