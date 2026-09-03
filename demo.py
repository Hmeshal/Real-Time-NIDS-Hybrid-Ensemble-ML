#demo.py
# replays demo.pcap offline, no admin or network needed

import os,time,json,warnings
import numpy as np,pandas as pd,joblib
from scapy.all import sniff,IP,TCP,UDP
warnings.filterwarnings("ignore")

MD="./Models"; ALERTS=MD+"/alerts.json"; LOGF=MD+"/live.log"
try:
    pipe=joblib.load(MD+"/Voting_pipeline.pkl"); FEATS=joblib.load(MD+"/feature_names.pkl"); cmap=joblib.load(MD+"/class_mapping.pkl")
except:
    print("train first"); exit()
if not os.path.exists("demo.pcap"): print("run generate_demo.py first"); exit()
# fresh logs each run so the dashboard only shows this replay
for _f in (ALERTS,LOGF):
    try: os.remove(_f)
    except: pass
flows,scans={},{}

def ms(x): return (float(np.mean(x)),float(np.std(x))) if x else (0.0,0.0)
def log(l):
    with open(LOGF,"a") as f: f.write(l+"\n")
def alert(rec,extra=""):
    with open(ALERTS,"a") as f: f.write(json.dumps(rec)+"\n")
    log("%s ALERT %s %s -> %s %s"%(rec["t"],rec["attack"],rec["src"],rec["dst"],extra))
    print("ALERT:",rec["attack"],rec["src"],"->",rec["dst"],extra)

def on_packet(p):
    if not p.haslayer(IP): return
    t=float(p.time) # pcap time, not real time
    try:
        s,d=p[IP].src,p[IP].dst; sp=dp=0
        if p.haslayer(TCP): sp,dp=p[TCP].sport,p[TCP].dport
        elif p.haslayer(UDP): sp,dp=p[UDP].sport,p[UDP].dport
        # sorted 5-tuple so both directions land in the same flow
        a,bg=sorted([(s,sp),(d,dp)]); k=(a[0],a[1],bg[0],bg[1],p[IP].proto)
        f=flows.get(k)
        if f is None: flows[k]=f={"src":s,"dst":d,"t0":t,"last":0,"fl":[],"bl":[],"iat":[],"flgs":""}
        if f["last"]: f["iat"].append(t-f["last"])
        f["last"]=t
        (f["fl"] if s==f["src"] else f["bl"]).append(len(p))
        if p.haslayer(TCP):
            f["flgs"]+=str(p[TCP].flags)
            if "S" in str(p[TCP].flags): scans.setdefault((s,d),{"t":t,"ports":set()})["ports"].add(dp)
    except Exception: pass

def feats(f):
    dur=max(f["last"]-f["t0"],1e-6); fl,bl,al=f["fl"],f["bl"],f["fl"]+f["bl"]
    iat=[i*1e6 for i in f["iat"]]; am,asd=ms(al); fm,fsd=ms(fl); bm,bsd=ms(bl); im,isd=ms(iat); g=f["flgs"]
    # keys must match feature_names.pkl exactly
    return {"Flow Duration":dur*1e6,"Total Fwd Packets":len(fl),"Total Bwd Packets":len(bl),
        "Fwd Packet Length Mean":fm,"Fwd Packet Length Std":fsd,"Fwd Packet Length Max":max(fl,default=0),"Fwd Packet Length Min":min(fl,default=0),
        "Bwd Packet Length Mean":bm,"Bwd Packet Length Std":bsd,"Bwd Packet Length Max":max(bl,default=0),"Bwd Packet Length Min":min(bl,default=0),
        "Flow Bytes/s":sum(al)/dur,"Flow Packets/s":len(al)/dur,"Flow IAT Mean":im,"Flow IAT Std":isd,
        "Flow IAT Max":max(iat,default=0),"Flow IAT Min":min(iat,default=0),
        "SYN Flag Count":g.count("S"),"FIN Flag Count":g.count("F"),"RST Flag Count":g.count("R"),
        "PSH Flag Count":g.count("P"),"ACK Flag Count":g.count("A"),"URG Flag Count":g.count("U"),
        "Down/Up Ratio":len(bl)/max(len(fl),1),"Average Packet Size":am,"Packet Length Mean":am,
        "Packet Length Std":asd,"Packet Length Variance":asd*asd,"Fwd Packets/s":len(fl)/dur,"Bwd Packets/s":len(bl)/dur,
        "Fwd Bytes/s":sum(fl)/dur,"Bwd Bytes/s":sum(bl)/dur,"Subflow Fwd Packets":len(fl),"Subflow Bwd Packets":len(bl),
        "Subflow Fwd Bytes":sum(fl),"Subflow Bwd Bytes":sum(bl)}

def decide(todo):
    vs=pipe.predict(pd.DataFrame([feats(f) for _,f in todo]).reindex(columns=FEATS))
    labs=[cmap[v] if v else None for v in vs]
    flood={}
    for i,(k,f) in enumerate(todo):
        # big syn-only flow the ml called dos (or missed) -> candidate
        if labs[i] in [None,"DoS"] and len(f["fl"])>=200 and not f["bl"] and f["flgs"].count("S")>=100:
            labs[i]="DoS"; flood.setdefault(f["dst"],set()).add(f["src"])
    # 3+ sources flooding the same dst = ddos
    for dst,srcs in flood.items():
        if len(srcs)>=3: labs=["DDoS" if l=="DoS" and f["dst"]==dst else l for l,(k,f) in zip(labs,todo)]
    sshc,webc={},{}
    for i,(k,f) in enumerate(todo):
        if labs[i]: continue
        dp=k[1] if f["dst"]==k[0] else k[3]
        if dp==22 and len(f["fl"])<=15: sshc[(f["src"],f["dst"])]=sshc.get((f["src"],f["dst"]),[])+[i]
        if dp==80 and len(f["fl"])<=8: webc[(f["src"],f["dst"])]=webc.get((f["src"],f["dst"]),[])+[i]
    # lots of tiny ssh flows from one src = brute force
    for _,ix in sshc.items():
        if len(ix)>=20:
            for i in ix: labs[i]="BruteForce"
    for _,ix in webc.items():
        if len(ix)>=10:
            for i in ix: labs[i]="Web Attack"
    for i,(k,f) in enumerate(todo):
        if labs[i]: continue
        fl,bl=f["fl"],f["bl"]; dur=max(f["last"]-f["t0"],1e-6); _,fsd=ms(fl)
        # steady same-size beacon = bot
        if dur>10 and 10<=len(fl)<=80 and fsd==0: labs[i]="Bot"
        # huge one-way transfer. router sends acks so bl can be >0 now
        elif sum(fl)>=100000 and len(fl)>100: labs[i]="Infiltration"
    return labs

print("reading demo.pcap ...")
sniff(offline="demo.pcap",prn=on_packet,store=0)
todo=list(flows.items())
labs=decide(todo) if todo else []
n=0
for (k,f),lab in zip(todo,labs):
    if lab: n+=1; alert({"t":time.strftime("%H:%M:%S"),"src":f["src"],"dst":f["dst"],"attack":lab})
log("checked %d flows, %d alert(s)"%(len(todo),n))
for kd,sc in scans.items():
    # 30+ ports from one pair = scan
    if len(sc["ports"])>=30:
        alert({"t":time.strftime("%H:%M:%S"),"src":kd[0],"dst":kd[1],"attack":"PortScan"},"(%d ports)"%len(sc["ports"]))
    #if len(sc["ports"])>=20:  <- old, flagged normal traffic
print(f"done - {n} alerts, open the dashboard")