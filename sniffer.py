#sniffer.py
# live detector, run as admin: python sniffer.py [iface name or number]

import sys,os,time,json,threading,traceback,warnings
import numpy as np,pandas as pd,joblib
from scapy.all import sniff,IP,TCP,UDP,IFACES,conf
warnings.filterwarnings("ignore")

MD="./Models"; ALERTS=MD+"/alerts.json"; LOGF=MD+"/live.log"
try:
    pipe=joblib.load(MD+"/Voting_pipeline.pkl"); FEATS=joblib.load(MD+"/feature_names.pkl"); cmap=joblib.load(MD+"/class_mapping.pkl")
except:
    print("train first"); exit()
flows,scans,scan_cd,pkt_count={},{},{},[0]
next_purge=time.time()+86400

# wipe logs older than a day
for _f in (ALERTS,LOGF):
    try:
        if time.time()-os.path.getmtime(_f)>86400: open(_f,"w").close()
    except: pass

def ms(x): return (float(np.mean(x)),float(np.std(x))) if x else (0.0,0.0)

def log(l):
    with open(LOGF,"a") as f: f.write(l+"\n")

def alert(rec,extra=""):
    with open(ALERTS,"a") as f: f.write(json.dumps(rec)+"\n")
    log("%s ALERT %s %s -> %s %s"%(rec["t"],rec["attack"],rec["src"],rec["dst"],extra))
    print("ALERT:",rec["attack"],rec["src"],"->",rec["dst"],extra)

def on_packet(p):
    pkt_count[0]+=1
    if pkt_count[0]%50==0: print("packets so far:",pkt_count[0])
    if not p.haslayer(IP): return
    t=time.time()
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
    except Exception as e:
        print("ERROR in on_packet:",e); traceback.print_exc()

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

def flush():
    now=time.time()
    # flow done when 2s old and 1s quiet, or 60s max
    todo=[(k,f) for k,f 
          in flows.items()
            if (now-f["t0"]>=2 and now-f["last"]>=1) or now-f["t0"]>=60]
    #todo=[(k,f) for k,f in flows.items() if now-f["t0"]>=5]  <- old, chopped bot beacons
    if todo:
        labs=decide(todo); n=0
        for (k,f),lab in zip(todo,labs):
            if lab: n+=1; alert({"t":time.strftime("%H:%M:%S"),"src":f["src"],"dst":f["dst"],"attack":lab})
            del flows[k]
        log("%s checked %d flows, %d alert(s)"%(time.strftime("%H:%M:%S"),len(todo),n))
    now=time.time()
    for kd in list(scans):
        sc=scans[kd]
        if now-sc["t"]<5: continue
        # 30+ ports in 5s = scan, 60s cooldown per pair
        if len(sc["ports"])>=30 and now-scan_cd.get(kd,0)>60:
            scan_cd[kd]=now
            alert({"t":time.strftime("%H:%M:%S"),"src":kd[0],"dst":kd[1],"attack":"PortScan"},"(%d ports)"%len(sc["ports"]))
        del scans[kd]

def start_sniff(iface):
    try: sniff(iface=iface,prn=on_packet,store=0)
    except Exception as e: print("sniff died:",e); traceback.print_exc()

if __name__=="__main__":
    q=sys.argv[1] if len(sys.argv)>1 else ""
    iface=None
    if q:
        for i in IFACES.values():
            if q in (i.name or "") or q in (i.description or "") or q==str(i.index): iface=i
    else:
        # no arg -> whatever iface has the default route
        try: iface=conf.route.route("0.0.0.0")[0]; print("auto-picked:",getattr(iface,"description",iface))
        except Exception: pass
    if iface is None:
        print("pick one:"); [print("  ",i.index,"-",i.description) for i in IFACES.values()]; exit()
    threading.Thread(target=start_sniff,args=(iface,),daemon=True).start()
    print("listening on",getattr(iface,"description",iface))
    while True:
        time.sleep(5)
        if time.time()>=next_purge:
            for _f in (ALERTS,LOGF):
                try: open(_f,"w").close()
                except: pass
            next_purge=time.time()+86400; print("logs purged (24h)")
        flush()