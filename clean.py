#clean.py
#raw csv -> cleaned csv

import os
import joblib
import numpy as np
import pandas as pd
from feature_engine.selection import DropConstantFeatures, DropDuplicateFeatures

fin = r'./Raw Merged-Dataset/PortScan-DDoS-Bot-Infiltration-WebAttacks-BruteForce-DoS-Bengin-Merged.csv'
fout = r'./Dataset/Cleaned-Multi-Class-Dataset.csv'

print("Loading:", fin)
data = pd.read_csv(fin, low_memory=False)  # dies if file missing, whatever

n0 = len(data)
data.columns = data.columns.str.strip()

if "Label" not in data.columns:
    print("no Label col")
    exit()

y = data["Label"].copy()
X = data.drop(columns=["Label"]).apply(pd.to_numeric, errors="coerce")

#dur 0 = broken
if "Flow Duration" in X.columns:
    print("Dropping Flow Duration == 0:", int((X["Flow Duration"] == 0).sum()))
    m = X["Flow Duration"] != 0
    X = X[m]
    y = y[m]

X.replace([np.inf, -np.inf], np.nan, inplace=True)

miss = X.isna().mean()
bad = miss[miss > 0.99].index.tolist()
if bad:
    print("dropping mostly empty cols:", bad)
    X = X.drop(columns=bad)

cs = DropConstantFeatures(tol=0.99)
X = cs.fit_transform(X)
ds = DropDuplicateFeatures()
X = ds.fit_transform(X)
print("constant dropped:", cs.features_to_drop_)
print("dup dropped:", ds.features_to_drop_)

# some csv versions keep these
hand_drop = ['Fwd Header Length.1',
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets', 'Subflow Bwd Packets',
        'Subflow Fwd Bytes', 'Subflow Bwd Bytes']
hd = [c for c in hand_drop if c in X.columns]
if hd:
    print("manual drop:", hd)
    X = X.drop(columns=hd)

tmp = pd.concat([X, y.rename("Label")], axis=1)
nBefore = len(tmp)
tmp = tmp.drop_duplicates()
print("dup rows removed:", nBefore - len(tmp))

X = tmp.drop(columns=["Label"])
y = tmp["Label"]

# the real 8 classes, heartbleed dropped (11 rows).
# bot stays separate, its its own thing not a flood
classMap = {0: "Benign", 1: "DDoS", 2: "PortScan", 3: "Bot",
        4: "BruteForce", 5: "WebAttack", 6: "DoS", 7: "Infiltration"}

def map_label(l):
    l = str(l).strip().lower()

    if l == "benign":
        return 0
    elif "ddos" in l:
        return 1
    elif "portscan" in l:
        return 2
    elif "bot" in l:
        return 3
    elif "web attack" in l:
        return 5
    elif "brute" in l or "patator" in l:
        return 4
    elif "infiltration" in l:
        return 7
    elif "dos" in l:
        return 6
    else:
        return -1  # heartbleed etc

def show_dist(yy):
    # quick class counts
    dist = yy.value_counts().sort_index()
    for cls in dist.index:
        nm = classMap.get(cls, cls)
        pct = dist[cls] / len(yy) * 100
        if pct < 1:
            print("%s: %d (%.2f%%)  <- tiny" % (nm, dist[cls], pct))
        else:
            print("%s: %d (%.2f%%)" % (nm, dist[cls], pct))

mp = y.apply(map_label)
print("\nmapping check:")
chk = pd.DataFrame({"Raw": y.astype(str),
        "Mapped": mp})
print(chk.drop_duplicates().sort_values("Mapped"))

ok = mp != -1
print("\nunknown dropped:", int((~ok).sum()))
X = X[ok]
y = mp[ok].astype(int)

print("\nclass dist:")
show_dist(y)

out = X.copy()
out["Label"] = y.values
out.reset_index(drop=True, inplace=True)

os.makedirs(os.path.dirname(fout), exist_ok=True)
out.to_csv(fout, index=False)
os.makedirs("./Models", exist_ok=True)
joblib.dump(classMap, "./Models/class_mapping.pkl")

print("\ndone. rows:", n0, "->", len(out))