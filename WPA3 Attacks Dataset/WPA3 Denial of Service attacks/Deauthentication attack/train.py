import pandas as pd
import matplotlib.pyplot as plt
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay

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

# 4. Train and evaluate
def run(name, columns, model):
    X, y = feat[columns], feat["label"]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    print(f"\n=== {name} ===")
    print("Accuracy:", accuracy_score(yte, pred))
    print(classification_report(yte, pred, target_names=["normal", "attack"]))
    ConfusionMatrixDisplay(confusion_matrix(yte, pred), display_labels=["normal", "attack"]).plot()
    plt.title(name)
    plt.savefig(name.replace(" ", "_") + ".png", dpi=200)
    return model

all_feats = ["total_frames", "deauth_frames", "deauth_ratio", "avg_len", "retry_ratio"]
no_deauth = ["total_frames", "avg_signal", "avg_len", "retry_ratio"]

rf = run("RF all features", all_feats, RandomForestClassifier(n_estimators=100, random_state=42))
run("DT all features", all_feats, DecisionTreeClassifier(max_depth=4, random_state=42))
run("RF without deauth features", no_deauth, RandomForestClassifier(n_estimators=100, random_state=42))

joblib.dump(rf, "wids_model.joblib")

split = int(len(feat) * 0.7)
tr, te = feat.iloc[:split], feat.iloc[split:]
m = RandomForestClassifier(n_estimators=100, random_state=42).fit(tr[no_deauth], tr["label"])
p = m.predict(te[no_deauth])
print("\n=== Time-based split, no deauth features ===")
print("Accuracy:", accuracy_score(te["label"], p))
print(confusion_matrix(te["label"], p))