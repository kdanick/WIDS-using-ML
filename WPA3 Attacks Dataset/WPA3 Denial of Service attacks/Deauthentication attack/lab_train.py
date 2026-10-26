import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix

F = ["total_frames", "avg_len", "retry_ratio"]   # no deauth count, no signal
pub = pd.read_csv("features.csv")
lab = pd.read_csv("features_lab.csv")

def run(name, tr, te):
    m = RandomForestClassifier(n_estimators=100, random_state=42).fit(tr[F], tr["label"])
    p = m.predict(te[F])
    print(f"\n=== {name} ===")
    print("Accuracy:", round(accuracy_score(te["label"], p), 4))
    print(confusion_matrix(te["label"], p, labels=[0, 1]))

run("Train public -> test lab", pub, lab)
run("Train lab -> test public", lab, pub)

early = lab[(lab["file"] == "normal") | ((lab["file"] == "attack") & (lab["window"] < 30))]
late = lab[(lab["file"] == "attack") & (lab["window"] >= 30)]
run("Lab time split (train early, test later)", early, late)