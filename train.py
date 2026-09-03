#train.py
# clean.py -> train.py -> evaluate.py

import os, time, joblib, numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import *
from sklearn.tree import DecisionTreeClassifier
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

SEED=42
MD="./Models"

def mk_w(y,cap=100.0):
    # inverse freq, capped
    cnt = pd.Series(y).value_counts()
    w = {}
    for c in cnt.index:
        w[int(c)] = len(y)/(len(cnt)*cnt[c])
    med = np.median(list(w.values()))
    out = {}
    for c in w:
        out[c] = float(min(w[c]/med,cap))
    return out

def mk_smote():
    # train split ONLY (leak otherwise)
    return SMOTE(sampling_strategy={3:20000,4:20000,5:20000,7:1000},
            k_neighbors=5,random_state=SEED)

def build_models(W,xgb_a):
    # trees get smote, boosters get weights
    mdl = {}
    mdl["RandomForest"] = ImbPipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("smote", mk_smote()),
        ("clf", RandomForestClassifier(n_estimators=500,
                class_weight=W, random_state=SEED, n_jobs=-1)),
    ])
    mdl["DecisionTree"] = ImbPipeline([("imputer",SimpleImputer(strategy="median")),("smote",mk_smote()),("clf",DecisionTreeClassifier(max_depth=30,class_weight=W,random_state=SEED))])
    mdl["LightGBM"] = Pipeline([("imputer",SimpleImputer(strategy="median")),("clf",LGBMClassifier(n_estimators=500,class_weight=W,random_state=SEED,n_jobs=-1,verbose=-1))])
    mdl["XGBoost"] = Pipeline([("imputer",SimpleImputer(strategy="median")),("clf",XGBClassifier(**xgb_a))])
    return mdl

def main():
    os.makedirs(MD,exist_ok=True)
    print("loading...")
    data = pd.read_csv("./Dataset/Cleaned-Multi-Class-Dataset.csv")
    try:
        cmap = joblib.load(MD+"/class_mapping.pkl")
    except:
        print("run clean.py first")
        exit()

    y = data["Label"].astype(int)
    X = data.drop(columns=["Label"]).apply(pd.to_numeric,errors="coerce")

    # ratio feats, trees liked these
    if "Total Length of Fwd Packets" in X.columns and "Total Length of Bwd Packets" in X.columns:
        X["Fwd_Bwd_Ratio"] = X["Total Length of Fwd Packets"]/(X["Total Length of Bwd Packets"]+1)
    if "Fwd Packet Length Mean" in X.columns and "Bwd Packet Length Mean" in X.columns:
        X["Packet_Size_Ratio"] = X["Fwd Packet Length Mean"]/(X["Bwd Packet Length Mean"]+1)
    X = X.replace([np.inf,-np.inf],np.nan)

    # drop empty / const cols
    junk = []
    for c in X.columns:
        if X[c].isna().mean() > 0.99 or X[c].nunique(dropna=True) <= 1:
            junk.append(c)
    if junk:
        X = X.drop(columns=junk)

    Xtr,Xte,ytr,yte = train_test_split(X,y,test_size=0.2,random_state=SEED,stratify=y)
    Xtr = Xtr.astype("float32") # ram
    Xte = Xte.astype("float32")
    #print(Xtr.shape)

    W = mk_w(ytr)
    print("weights:",W)

    # 900 rounds @0.05 = 2x time, same score
    xgb_a = dict(n_estimators=500,learning_rate=0.08,min_child_weight=0.5,random_state=SEED,n_jobs=-1,eval_metric="mlogloss")
    sw = np.sqrt(ytr.map(W).astype(float).values) # sqrt fixed xgb ranking
    #sw = ytr.map(W).astype(float).values  <- old, broke ranking

    mdl = build_models(W,xgb_a)

    tt = {}
    for n in mdl:
        print("training",n)
        t1 = time.time()
        if n=="XGBoost":
            mdl[n].fit(Xtr,ytr,clf__sample_weight=sw)
        else:
            mdl[n].fit(Xtr,ytr)
        tt[n] = round(time.time()-t1,2)
        joblib.dump(mdl[n],MD+"/"+n+"_pipeline.pkl")
        print("  %s: %.2fs" % (n,tt[n]))

    # [rf,lgb,xgb]. xgb ignores class_weight in this build -> votes plain
    vote_w = [4,2,1]
    xgb_v = XGBClassifier(**xgb_a)
    print("training Voting")
    t0 = time.time()
    vote = VotingClassifier(
        estimators=[
            ("rf", ImbPipeline([
                ("imputer", SimpleImputer(strategy="median")),
                ("smote", mk_smote()),
                ("clf", RandomForestClassifier(n_estimators=250,
                        class_weight=W, random_state=SEED, n_jobs=-1)),
            ])),
            ("lgb", LGBMClassifier(n_estimators=500,class_weight=W,random_state=SEED,n_jobs=-1,verbose=-1)),
            ("xgb", xgb_v),
        ],
        voting="soft",
        weights=vote_w)
    stk = Pipeline([("imputer",SimpleImputer(strategy="median")),("v",vote)])
    stk.fit(Xtr,ytr)
    tt["Voting"] = round(time.time()-t0,2)
    joblib.dump(stk,MD+"/Voting_pipeline.pkl")
    print(f"  voting: {tt['Voting']}s")

    # for evaluate.py
    fnames = list(X.columns)
    joblib.dump(fnames,MD+"/feature_names.pkl")
    joblib.dump(Xtr,MD+"/Xtrain.pkl")
    joblib.dump(ytr,MD+"/ytrain.pkl")
    joblib.dump(Xte,MD+"/Xtest.pkl")
    joblib.dump(yte,MD+"/ytest.pkl")
    joblib.dump(tt,MD+"/train_time.pkl")
    joblib.dump(cmap,MD+"/class_mapping.pkl")
    print("done:",tt)

if __name__ == "__main__":
    main()