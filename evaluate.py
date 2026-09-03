#evaluate.py
# train.py 1st
# TODO per-class plots later

import os, joblib, numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import *

MD="./Models"

# one model
def eval_one(pipe,Xte,yte,classMap):
    pr = pipe.predict(Xte)
    acc = accuracy_score(yte,pr)
    f1m = f1_score(yte,pr,average="macro")
    roc = None
    try:
        roc = roc_auc_score(yte,pipe.predict_proba(Xte),multi_class="ovr",average="macro")
    except:
        print("  roc skipped")  # whatever
    rep = classification_report(yte,pr,labels=list(classMap.keys()),
            target_names=list(classMap.values()),output_dict=True,zero_division=0)
    return {"acc":acc,"f1":f1m,"roc":roc,"pred":pr,"report":rep}

def main():
    Xte = joblib.load(MD+"/Xtest.pkl")
    yte = pd.Series(joblib.load(MD+"/ytest.pkl")).astype(int)
    lm = joblib.load(MD+"/class_mapping.pkl")
    classMap = {int(k):str(v) for k,v in lm.items()}
    Xte = Xte.reindex(columns=joblib.load(MD+"/feature_names.pkl"))

    names = ["RandomForest","DecisionTree","LightGBM","XGBoost","Voting"]
    res = {}

    for m in names:
        if m=="Voting":
            p = MD+"/Voting_pipeline.pkl"
        else:
            p = MD+"/"+m+"_pipeline.pkl"
        if not os.path.exists(p):
            continue
        print("evaluating",m)
        pipe = joblib.load(p)
        r = eval_one(pipe,Xte,yte,classMap)
        res[m] = r
        print("  %s | acc %.4f | f1 %.4f" % (m,r["acc"],r["f1"]))

    rows = []
    for m in res:
        rows.append([m,res[m]["f1"],res[m]["acc"],res[m]["roc"]])
    df = pd.DataFrame(rows,columns=["Model","Test F1","Test Acc","ROC-AUC"])
    print(df.to_string(index=False))
    df.to_csv(MD+"/evaluation_summary.csv",index=False)

    for m in res:
        pd.DataFrame(res[m]["report"]).T.to_csv(MD+"/"+m+"_report.csv")

    # pics
    confusion_matrix_folder = MD+"/confusion_matrices"
    os.makedirs(confusion_matrix_folder,exist_ok=True)
    for m in res:
        cm = confusion_matrix(yte,res[m]["pred"],labels=list(classMap.keys()))
        plt.figure(figsize=(10,8))
        sns.heatmap(cm,annot=True,fmt="d",cmap="Blues",
                xticklabels=list(classMap.values()),
                yticklabels=list(classMap.values()))
        plt.title(m)
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.tight_layout()
        plt.savefig(confusion_matrix_folder+"/"+m+"_cm.png",dpi=300)
        plt.close()

    bestM = df.loc[df["Test F1"].idxmax(),"Model"]
    print("\nBEST:",bestM)
    rep = pd.DataFrame(res[bestM]["report"]).T
    print(rep.loc[list(classMap.values())][["precision","recall","f1-score"]].to_string())
    print("done")

if __name__ == "__main__":
    main()