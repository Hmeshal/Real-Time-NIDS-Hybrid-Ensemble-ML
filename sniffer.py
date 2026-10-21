#sniffer.py v3 - live detector, run as admin: python sniffer.py [iface]
import sys,os,time,json,threading,traceback,warnings
from collections import deque
import numpy as np,pandas as pd,joblib
from scapy.all import sniff,IP,TCP,UDP,IFACES,conf
warnings.filterwarnings("ignore")

MD="./Models"; ALERTS=MD+"/alerts.json"; LOGF=MD+"/live.log"
try:
    pipe=joblib.load(MD+"/Voting_pipeline.pkl"); FEATS=joblib.load(MD+"/feature_names.pkl"); cmap=joblib.load(MD+"/class_mapping.pkl")
except: print("train first"); exit()

flows,scans,scan_cd,cnt={},{},{},[0]
webc,brute,beacon,beacon_cd,web_cd,brute_cd,flood,flooding={},{},{},{},{},{},{},{}
fl_recent={}; mlv={}; last_alert={}; hist={}
lock=threading.Lock()

WIN=5; DOS=500            # flood window (s) / packets in window
COOL=60                   # same (src,dst,attack) not re-alerted within COOL s
SUP=20                    # stronger alert suppresses weaker ones on same target for SUP s
MLV=3                     # ML needs >=3 flows of same (src,dst,class) within 30s

PRI={"DDoS":0,"DoS":1,"PortScan":2,"BruteForce":3,"Infiltration":4,"Web Attack":5,"Bot":6}
NORM={"Brute Force":"BruteForce","WebAttack":"Web Attack","Port Scan":"PortScan"}
def norm(x): return NORM.get(x,x) if x is not None else None

for _f in (ALERTS,LOGF):
    try:
        if time.time()-os.path.getmtime(_f)>86400: open(_f,"w").close()
    except: pass

def ms(x): return (float(np.mean(x)),float(np.std(x))) if x else (0.0,0.0)
def log(l):
    with open(LOGF,"a") as f: f.write(l+"\n")
def ts(): return time.strftime("%H:%M:%S")
def alert(r,x=""):
    with open(ALERTS,"a") as f: f.write(json.dumps(r)+"\n")
    log("%s ALERT %s %s -> %s %s"%(r["t"],r["attack"],r["src"],r["dst"],x))
    print("ALERT:",r["attack"],r["src"],"->",r["dst"],x)

def beat(times):
    if len(times)<10: return 0.0
    g=np.diff(times[-10:]); m=float(np.mean(g))
    return m if (0.5<m<10 and float(np.std(g))/max(m,1e-6)<0.35) else 0.0

def is_flood(fa):
    # only SYN-like packets are counted in fa["t"] now (SYN, UDP, ICMP)
    return len(fa["t"])>=DOS

def on_packet(p):
    cnt[0]+=1
    if cnt[0]%500==0: print("packets so far:",cnt[0])
    if not p.haslayer(IP): return
    t=time.time()
    try:
        s,d=p[IP].src,p[IP].dst; sp=dp=0; g=""; tcp=p.haslayer(TCP)
        if tcp: sp,dp=p[TCP].sport,p[TCP].dport; g=str(p[TCP].flags)
        elif p.haslayer(UDP): sp,dp=p[UDP].sport,p[UDP].dport
        a,b=sorted([(s,sp),(d,dp)]); k=(a[0],a[1],b[0],b[1],p[IP].proto)
        L=len(p)
        syn="S" in g and "A" not in g
        reply=tcp and (("S" in g and "A" in g) or "R" in g)
        synlike=syn or not tcp
        if tcp: cli=True if syn else (False if "S" in g else sp>=dp)
        else: cli=True
        with lock:
            if not reply:
                fa=flood.get((d,dp))
                if fa is None or t-fa["last"]>WIN:
                    fa=flood[(d,dp)]={"t":deque(maxlen=DOS*4),"srcs":{},"last":t,"al":0}
                # THE FIX: only SYN-like packets count toward a flood
                if synlike: fa["t"].append(t)
                fa["srcs"][s]=t; fa["last"]=t
                cut=t-WIN
                while fa["t"] and fa["t"][0]<cut: fa["t"].popleft()
                if is_flood(fa):
                    flooding[(d,dp)]=t+WIN; fl_recent[d]=t; fa["hit"]=t
                    fa["pk"]=max(fa.get("pk",0),len(fa["t"]))
                    if t-fa.get("nsck",0)>0.5:
                        fa["nsck"]=t; fa["ns"]=max(fa.get("ns",0),sum(1 for lt in fa["srcs"].values() if t-lt<=WIN))
            if synlike and flooding.get((d,dp),0)>t: return
            if reply and flooding.get((s,sp),0)>t: return
            f=flows.get(k)
            if f is None:
                cs,cd,cp=(s,d,dp) if cli else (d,s,sp)
                flows[k]=f={"src":cs,"dst":cd,"dp":cp,"t0":t,"last":0,"fl":[],"bl":[],"iat":[],"g":"","fs":set()}
            if f["last"]: f["iat"].append(t-f["last"])
            f["last"]=t
            if s==f["src"]:
                f["fl"].append(L)
                if len(f["fs"])<3: f["fs"].add(L)
            else: f["bl"].append(L)
            if g:
                f["g"]+=g
                if syn: scans.setdefault((s,d),{"t":t,"ports":set()})["ports"].add(dp)
    except Exception as e: print("ERROR:",e); traceback.print_exc()

def feats(f):
    dur=max(f["last"]-f["t0"],1e-6); fl,bl,al=f["fl"],f["bl"],f["fl"]+f["bl"]
    iat=[i*1e6 for i in f["iat"]]; am,asd=ms(al); fm,fsd=ms(fl); bm,bsd=ms(bl); im,isd=ms(iat); g=f["g"]
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
    t=time.time(); labs=[]
    for i,(k,f) in enumerate(todo):
        lab=norm(cmap[vs[i]] if vs[i] is not None else None)
        fl,bl,g=f["fl"],f["bl"],f["g"]; syn=g.count("S"); src,dst,dp=f["src"],f["dst"],f["dp"]
        busy=t-fl_recent.get(dst,0)<30
        if lab not in PRI: lab=None
        if lab in ("DoS","DDoS") and not busy: lab=None
        if lab=="Infiltration": lab=None
        # Prevent ML from misclassifying SSH brute-force as Web Attack
        if lab=="Web Attack" and dp not in (80,443,8080): lab=None
        if lab and lab not in ("DoS","DDoS"):
            q=mlv.setdefault((src,dst,lab),deque(maxlen=20)); q.append(t)
            while q and t-q[0]>30: q.popleft()
            if len(q)<MLV: lab=None
        if len(fl)>=200 and syn>=100 and (not bl or syn>=0.5*len(fl)): lab="DoS"
        sf=sum(fl)
        if lab!="DoS" and sf>=100000 and len(fl)>100 and syn<=3 and sf>2*sum(bl) and not busy:
            lab="Infiltration"
        if lab is None:
            quiet=flooding.get((dst,dp),0)<=t and not busy
            if dp==80 and len(fl)<=8 and quiet:
                r=webc.setdefault((src,dst),{"c":0,"t":0,"ts":[]}); r["c"]+=1; r["t"]=t; r["ts"]=(r["ts"]+[f["t0"]])[-30:]
            elif dp in (22,21) and len(fl)<=15 and quiet:
                r=brute.setdefault((src,dst),{"c":0,"t":0}); r["c"]+=1; r["t"]=t
            else:
                dur=max(f["last"]-f["t0"],1e-6); _,fsd=ms(fl)
                if dur>10 and 10<=len(fl)<=80 and fsd<20 and len(f["fs"])<=2: lab="Bot"
        labs.append(lab)
    return labs

def emit(pend):
    t=time.time()
    pend.sort(key=lambda z:PRI.get(z[0]["attack"],9))
    for r,x in pend:
        a=r["attack"]; p=PRI.get(a,9); src,dst=r["src"],r["dst"]
        h=hist[dst]=[e for e in hist.get(dst,[]) if t-e[0]<SUP]
        if p>1 and t-fl_recent.get(dst,0)<SUP: continue
        if any(hp<p and (hp<=1 or hs==src) for _,hp,hs in h): continue
        h.append((t,p,src))
        kk=(src,dst,a)
        if t-last_alert.get(kk,0)<COOL: continue
        last_alert[kk]=t; alert(r,x)

def flush():
    t=time.time(); pend=[]
    with lock:
        todo=[(k,f) for k,f in flows.items() if (t-f["t0"]>=2 and t-f["last"]>=1) or t-f["t0"]>=60]
        for k,_ in todo: del flows[k]
    labs=decide(todo) if todo else []
    for (k,f),lab in zip(todo,labs):
        if lab is None and len(f["fl"])<=15 and len(f["fl"])+len(f["bl"])<=25:
            r=beacon.setdefault((f["src"],f["dst"],f["dp"]),{"s":[],"t":0})
            r["s"]=(r["s"]+[f["t0"]])[-30:]; r["t"]=t
        if lab: pend.append(({"t":ts(),"src":f["src"],"dst":f["dst"],"attack":lab},""))
    if todo: log("%s checked %d flows, %d alert(s)"%(ts(),len(todo),sum(1 for l in labs if l)))
    with lock:
        for key,r in list(beacon.items()):
            if t-r["t"]>20: del beacon[key]; continue
            m=beat(r["s"])
            if m and t-beacon_cd.get(key[:2],0)>60:
                beacon_cd[key[:2]]=t
                pend.append(({"t":ts(),"src":key[0],"dst":key[1],"attack":"Bot"},"(beacon %.1fs)"%m)); del beacon[key]
        for key,fa in list(flood.items()):
            if t-fa["last"]>10: del flood[key]; continue
            if not fa.get("hit"): continue
            ns=fa.get("ns",1)
            srcs=sorted(x for x,lt in fa["srcs"].items() if fa["last"]-lt<=WIN)[:3]
            for wk in [k for k in webc if k[1]==key[0]]: del webc[wk]
            for bk in [k for k in brute if k[1]==key[0]]: del brute[bk]
            pend.append(({"t":ts(),"src":",".join(srcs),"dst":key[0],"attack":"DDoS" if ns>=3 else "DoS"},
                         "(%d pkts/5s, %d srcs)"%(fa.get("pk",0),ns)))
            fa["hit"]=0; fa["pk"]=0; fa["ns"]=0
        for key,r in list(webc.items()):
            if t-r["t"]>30 or (r["c"]>=10 and t-web_cd.get(key,0)<60): del webc[key]
            elif r["c"]>=10:
                if beat(r["ts"]): continue
                web_cd[key]=t; pend.append(({"t":ts(),"src":key[0],"dst":key[1],"attack":"Web Attack"},"")); del webc[key]
        for key,r in list(brute.items()):
            if t-r["t"]>60 or (r["c"]>=20 and t-brute_cd.get(key,0)<60): del brute[key]
            elif r["c"]>=20:
                brute_cd[key]=t; pend.append(({"t":ts(),"src":key[0],"dst":key[1],"attack":"BruteForce"},"")); del brute[key]
        for kd in list(scans):
            sc=scans[kd]
            if t-sc["t"]>=5:
                if len(sc["ports"])>=30 and t-scan_cd.get(kd,0)>60:
                    scan_cd[kd]=t; pend.append(({"t":ts(),"src":kd[0],"dst":kd[1],"attack":"PortScan"},"(%d ports)"%len(sc["ports"])))
                del scans[kd]
        for kd in [k for k,v in flooding.items() if v<t]: del flooding[kd]
        for kd in [k for k,v in fl_recent.items() if t-v>120]: del fl_recent[kd]
    for kd in [k for k,q in mlv.items() if not q or t-q[-1]>60]: del mlv[kd]
    for kd in [k for k,v in last_alert.items() if t-v>600]: del last_alert[kd]
    emit(pend)

if __name__=="__main__":
    q=sys.argv[1] if len(sys.argv)>1 else ""; iface=None
    if q:
        for i in IFACES.values():
            if q in (i.name or "") or q in (i.description or "") or q==str(i.index): iface=i
    else:
        try: iface=conf.route.route("0.0.0.0")[0]; print("auto-picked:",getattr(iface,"description",iface))
        except: pass
    if iface is None:
        print("pick one:"); [print(" ",i.index,"-",i.description) for i in IFACES.values()]; exit()
    threading.Thread(target=lambda: sniff(iface=iface,prn=on_packet,store=0),daemon=True).start()
    print("listening on",getattr(iface,"description",iface))
    nxt=time.time()+86400
    while True:
        time.sleep(5); flush()
        if time.time()>=nxt:
            for _f in (ALERTS,LOGF):
                try: open(_f,"w").close()
                except: pass
            nxt=time.time()+86400; print("logs purged (24h)")