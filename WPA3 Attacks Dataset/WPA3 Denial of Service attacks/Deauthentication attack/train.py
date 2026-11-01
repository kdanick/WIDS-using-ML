import pandas as pd
import matplotlib.pyplot as plt
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay

# Plot and save a confusion matrix with accuracy and interpretation notes.
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

# 1. Load only the columns we need
cols = ["frame.time_relative", "frame.len", "radiotap.dbm_antsignal",
        "wlan.fc.type_subtype", "wlan.fc.retry", "Label"]
df = pd.read_csv("Deauth.csv", usecols=cols, low_memory=False)
for c in cols[:-1]:
    df[c] = pd.to_numeric(df[c], errors="coerce")

# 2. Per-frame helpers and 1-second windows
df["window"] = df["frame.time_relative"].fillna(0).astype(int)
df["is_deauth"] = (df["wlan.fc.type_subtype"] == 12).astype(int)
df["is_attack"] = (df["Label"] == "Deauth").astype(int)

# 3. Feature extraction: one row per second
g = df.groupby("window")
feat = pd.DataFrame({
    "total_frames": g.size(),
    "deauth_frames": g["is_deauth"].sum(),
    "avg_signal": g["radiotap.dbm_antsignal"].mean(),
    "avg_len": g["frame.len"].mean(),
    "retry_ratio": g["wlan.fc.retry"].mean(),
    "label": g["is_attack"].max().astype(int),
})
feat["deauth_ratio"] = feat["deauth_frames"] / feat["total_frames"]
feat = feat.fillna(feat.median())
feat.to_csv("features.csv")
print("Windows:", len(feat))
print(feat["label"].value_counts())

# 4. Main detector: all features, random 70/30 split
all_feats = ["total_frames", "deauth_frames", "deauth_ratio", "avg_signal", "avg_len", "retry_ratio"]
Xtr, Xte, ytr, yte = train_test_split(feat[all_feats], feat["label"],
                                      test_size=0.3, stratify=feat["label"], random_state=42)
rf = RandomForestClassifier(n_estimators=100, random_state=42).fit(Xtr, ytr)
pred = rf.predict(Xte)
print("\n=== Detector (all features) ===")
print("Accuracy:", accuracy_score(yte, pred))
print(classification_report(yte, pred, target_names=["normal", "attack"]))
save_cm(yte, pred,
        "Random Forest deauth flood detector",
        f"Tested on {len(yte)} unseen seconds of the WPA3 dataset (30% held out from training)",
        "CM_WPA3_test.png")
joblib.dump(rf, "wids_model.joblib")

# 5. Check: no deauth count, train on earlier seconds, test on later ones
no_deauth = ["total_frames", "avg_signal", "avg_len", "retry_ratio"]
split = int(len(feat) * 0.7)
tr, te = feat.iloc[:split], feat.iloc[split:]
m = RandomForestClassifier(n_estimators=100, random_state=42).fit(tr[no_deauth], tr["label"])
p = m.predict(te[no_deauth])
print("\n=== Time-based split, no deauth features ===")
print("Accuracy:", accuracy_score(te["label"], p))
print(confusion_matrix(te["label"], p))
save_cm(te["label"], p,
        "Check: model that never sees the deauth frame count",
        f"Trained on the first 70% of seconds, tested on the last {len(te)} seconds",
        "CM_WPA3_timesplit_no_deauth.png")