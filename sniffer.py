#sniffer.py - live detector, run as admin: python sniffer.py [iface]
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
# persistent across flushes so slow real-tool attacks still accumulate
webc_state,brute_state,flood_state,beacon_state,beacon_cd={},{},{},{},{}

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
        a,bg=sorted([(s,sp),(d,dp)]); k=(a[0],a[1],bg[0],bg[1],p[IP].proto)
        f=flows.get(k)
        if f is None: flows[k]=f={"src":s,"dst":d,"dp":dp,"t0":t,"last":0,"fl":[],"bl":[],"iat":[],"flgs":""}
        if f["last"]: f["iat"].append(t-f["last"])
        f["last"]=t
        (f["fl"] if s==f["src"] else f["bl"]).append(len(p))
        if p.haslayer(TCP):
            f["flgs"]+=str(p[TCP].flags)
            # initial SYN only, SYN-ACK replies dont count (keeps nmap/hping clean)
            if "S" in str(p[TCP].flags) and "A" not in str(p[TCP].flags):
                scans.setdefault((s,d),{"t":t,"ports":set()})["ports"].add(dp)
    except Exception as e:
        print("ERROR:",e); traceback.print_exc()

def feats(f):
    dur=max(f["last"]-f["t0"],1e-6); fl,bl,al=f["fl"],f["bl"],f["fl"]+f["bl"]
    iat=[i*1e6 for i in f["iat"]]; am,asd=ms(al); fm,fsd=ms(fl); bm,bsd=ms(bl); im,isd=ms(iat); g=f["flgs"]
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
    now=time.time()
    for i,(k,f) in enumerate(todo):
        fl,bl,g=f["fl"],f["bl"],f["flgs"]; syn=g.count("S")
        # DoS: one-way flood OR SYN-dominated flood (hping3 to an OPEN port gets SYN-ACKs back)
        if labs[i] in [None,"DoS"] and len(fl)>=200 and syn>=100 and (not bl or syn>=0.5*len(fl)):
            labs[i]="DoS"
            rec=flood_state.setdefault(f["dst"],{"srcs":set(),"last":0})
            rec["srcs"].add(f["src"]); rec["last"]=now
        if labs[i]: continue
        dp=f["dp"]
        # web: small http flows accumulate over 30s (sqlmap / curl bursts)
        if dp==80 and len(fl)<=8:
            rec=webc_state.setdefault((f["src"],f["dst"]),{"count":0,"last":0})
            rec["count"]+=1; rec["last"]=now
        # brute: small ssh/ftp flows accumulate over 60s (hydra is slower than scapy)
        elif dp in (22,21) and len(fl)<=15:
            rec=brute_state.setdefault((f["src"],f["dst"]),{"count":0,"last":0})
            rec["count"]+=1; rec["last"]=now
        else:
            dur=max(f["last"]-f["t0"],1e-6); _,fsd=ms(fl)
            # bot: one long uniform beacon (netcat style)
            if dur>10 and 10<=len(fl)<=80 and fsd<20 and len(set(fl))<=2: labs[i]="Bot"
            # infiltration: big one-way transfer (nc / dd / curl upload)
            elif sum(fl)>=100000 and len(fl)>100: labs[i]="Infiltration"
    return labs

def flush():
    now=time.time()
    todo=[(k,f) for k,f in flows.items() if (now-f["t0"]>=2 and now-f["last"]>=1) or now-f["t0"]>=60]
    if todo:
        labs=decide(todo); n=0
        for (k,f),lab in zip(todo,labs):
            # feed beacon tracker with quiet small flows only
            if lab is None and len(f["fl"])<=15 and len(f["fl"])+len(f["bl"])<=25:
                rec=beacon_state.setdefault((f["src"],f["dst"],f["dp"]),{"starts":[],"last":0})
                rec["starts"].append(f["t0"]); rec["last"]=now
                if len(rec["starts"])>30: rec["starts"]=rec["starts"][-30:]
            if lab: n+=1; alert({"t":time.strftime("%H:%M:%S"),"src":f["src"],"dst":f["dst"],"attack":lab})
            del flows[k]
        log("%s checked %d flows, %d alert(s)"%(time.strftime("%H:%M:%S"),len(todo),n))
        # cross-flow beacon: regular small connections = curl-style bot
        for key,rec in list(beacon_state.items()):
            if now-rec["last"]>20: del beacon_state[key]; continue
            st=rec["starts"]
            if len(st)>=10:
                gaps=[b-a for a,b in zip(st[-10:],st[-9:])]
                m=float(np.mean(gaps)); sd=float(np.std(gaps)); kd=(key[0],key[1])
                if 0.5<m<10 and sd/max(m,1e-6)<0.35 and now-beacon_cd.get(kd,0)>60:
                    beacon_cd[kd]=now
                    alert({"t":time.strftime("%H:%M:%S"),"src":key[0],"dst":key[1],"attack":"Bot"},"(beacon %.1fs interval)"%m)
                    del beacon_state[key]
    # persistent thresholds
    for dst,rec in list(flood_state.items()):
        if now-rec["last"]>45: del flood_state[dst]
        elif len(rec["srcs"])>=3:
            alert({"t":time.strftime("%H:%M:%S"),"src":",".join(sorted(rec["srcs"])),"dst":dst,"attack":"DDoS"})
            del flood_state[dst]
    for key,rec in list(webc_state.items()):
        if now-rec["last"]>30: del webc_state[key]
        elif rec["count"]>=10:
            alert({"t":time.strftime("%H:%M:%S"),"src":key[0],"dst":key[1],"attack":"Web Attack"})
            del webc_state[key]
    for key,rec in list(brute_state.items()):
        if now-rec["last"]>60: del brute_state[key]
        elif rec["count"]>=20:
            alert({"t":time.strftime("%H:%M:%S"),"src":key[0],"dst":key[1],"attack":"BruteForce"})
            del brute_state[key]
    for kd in list(scans):
        sc=scans[kd]
        if now-sc["t"]<5: continue
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