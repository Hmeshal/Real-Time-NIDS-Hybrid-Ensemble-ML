#app.py - flask dashboard
from flask import Flask,render_template_string,request,jsonify
import pandas as pd,json,os

MD="./Models"
C=["#4da3ff","#3ecf6f","#ff5c5c","#f0b429","#a78bfa","#8b98a1"]
ROW={"PortScan":"#1d3a52","DoS":"#4a2626","DDoS":"#4a2626","BruteForce":"#4a3d1d","Web Attack":"#37294a","Bot":"#23402c","Infiltration":"#4a3123"}
BDG={"PortScan":"#2d5a8f","DoS":"#8f2d2d","DDoS":"#8f2d2d","BruteForce":"#8f6d2d","Web Attack":"#5a2d8f","Bot":"#2d6b3a","Infiltration":"#8f4a1f"}
app=Flask(__name__)

TPL="""<!doctype html><html data-bs-theme="dark"><head><meta charset="utf-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>Chart.defaults.color="#9aa0a6";Chart.defaults.borderColor="#2e3236"</script>
<style>body{background:#232629;color:#d4d7da;font:14px Segoe UI,Arial}
.mb{background:#2a2d31;border-bottom:1px solid #3a3d42;padding:8px 16px;display:flex;align-items:center}
.mb b{font-size:16px;margin-right:18px}.mb a{color:#d4d7da;text-decoration:none;padding:5px 12px;border-radius:3px}
.mb a.on{background:#39434f;font-weight:600}main{padding:14px 18px 30px}h1{font-size:16px;margin:14px 0 6px}
table{width:100%;border-collapse:collapse;background:#26292d;border:1px solid #3a3d42;margin:10px 0}
th{background:#2f3237;padding:5px 10px;text-align:left;font-size:13px}
td{padding:4px 10px;border-bottom:1px solid #2e3236;font:13px Consolas}
pre{background:#16181a;border:1px solid #3a3d42;border-radius:4px;padding:10px;font:12px Consolas;color:#8fd18f;white-space:pre-wrap}
.box{background:#26292d;border:1px solid #3a3d42;border-radius:4px;padding:10px;margin:10px 0}</style></head><body>
<div class="mb"><b>Dashboard</b>
<a href="/alerts" class="{{'on' if p=='a' else ''}}">Alerts</a>
<a href="/" class="{{'on' if p=='m' else ''}}">Models</a>
<a href="/compare" class="{{'on' if p=='c' else ''}}">Compare</a>
<a href="/help" class="{{'on' if p=='h' else ''}}">Runbook</a></div>
<main>{{b|safe}}</main></body></html>"""

def chip(n): return f"<span style='background:{BDG.get(n,'#3a3d42')};color:#fff;padding:2px 8px;border-radius:3px;font-weight:600;font-size:12px'>{n}</span>"

def chart(cid,labels,ds,ymax=None,legend=False,typ="bar"):
    if typ=="doughnut" and ds and "data" in ds[0]:
        total=sum(ds[0]["data"])
        if total>0: labels=[f"{l} ({round(v/total*100,1)}%)" for l,v in zip(labels,ds[0]["data"])]
    opts={"plugins":{"legend":{"display":legend,"labels":{"color":"#d4d7da","font":{"size":14}}}}}
    if typ=="bar": opts["scales"]={"y":{"beginAtZero":True,"max":ymax} if ymax else {"beginAtZero":True}}
    h,w=("450px","600px") if typ=="doughnut" else ("350px","900px")
    return f"<div style='max-width:{w};margin:20px auto;'><div class='box' style='height:{h}'><canvas id='{cid}'></canvas></div></div><script>window.{cid}=new Chart(document.getElementById('{cid}'),{{type:'{typ}',data:{{labels:{json.dumps(list(labels))},datasets:{json.dumps(ds)}}},options:{json.dumps(opts)}}})</script>"

@app.route("/api/alerts")
def api_alerts():
    try: allr=[json.loads(l) for l in open(MD+"/alerts.json") if l.strip()]
    except: allr=[]
    return jsonify(allr)

@app.route("/api/logs")
def api_logs():
    try: return "\n".join(open(MD+"/live.log",errors="ignore").read().splitlines()[-20:])
    except: return "Sniffer not running."

@app.route("/alerts")
def alerts():
    try: allr=[json.loads(l) for l in open(MD+"/alerts.json") if l.strip()]
    except: allr=[]
    q=request.args.get("q","")
    rows=[r for r in allr if q.lower() in (r["attack"]+r["src"]+r["dst"]).lower()] if q else allr
    b="<h1 class='text-center'>Live Alerts</h1>"
    b+=f"<div class='text-center mb-3'><form action='/alerts' class='d-inline-block'><div class='input-group' style='width:560px;'><input class='form-control' name='q' value='{q}' placeholder='filter'><button class='btn btn-secondary'>Apply</button></div></form> <a class='btn btn-outline-danger ms-2' href='/clear'>Clear Logs</a></div>"
    ty=pd.Series([r["attack"] for r in rows]).value_counts() if rows else pd.Series(dtype=int)
    mins=pd.Series([r["t"][:5] for r in rows]).value_counts().sort_index() if rows else pd.Series(dtype=int)
    pie_ds=[{'data':[int(x) for x in ty.values],'backgroundColor':[BDG.get(l,'#3a3d42') for l in ty.index]}]
    b+=f"<div class='row'><div class='col-lg-6'>{chart('c0',ty.index,pie_ds,legend=True,typ='doughnut')}</div>"
    b+=f"<div class='col-lg-6'>{chart('c1',mins.index,[{'label':'alerts','data':[int(x) for x in mins.values],'backgroundColor':'#ff5c5c'}])}</div></div>"
    b+="<table id='alert-table'><tr><th>No.</th><th>Time</th><th>Source</th><th>Target</th><th>Attack</th></tr>"
    if rows:
        for n,r in enumerate(rows[-100:][::-1],1):
            b+=f"<tr style='background:{ROW.get(r['attack'],'#26292d')}'><td>{n}</td><td>{r['t']}</td><td>{r['src']}</td><td>{r['dst']}</td><td>{chip(r['attack'])}</td></tr>"
    else: b+="<tr><td colspan='5' class='text-center text-secondary py-4'>Waiting for attacks...</td></tr>"
    b+="</table>"
    try: log_txt="\n".join(open(MD+"/live.log",errors="ignore").read().splitlines()[-20:])
    except: log_txt="Sniffer not running."
    b+=f"<h1 class='text-center'>Sniffer Console</h1><pre id='console-pre'>{log_txt}</pre>"
    b+=f"""<script>
    const ROW={json.dumps(ROW)}; const BDG={json.dumps(BDG)}; const currentFilter='{q}';
    setInterval(()=>{{
        if(document.activeElement.tagName==='INPUT')return;
        fetch('/api/alerts').then(r=>r.json()).then(data=>{{
            if(currentFilter){{const qf=currentFilter.toLowerCase();data=data.filter(r=>(r["attack"]+r["src"]+r["dst"]).toLowerCase().includes(qf));}}
            const t=document.getElementById('alert-table');
            if(t){{let h='<tr><th>No.</th><th>Time</th><th>Source</th><th>Target</th><th>Attack</th></tr>';
            for(let i=data.length-1;i>=0;i--){{const r=data[i];
            h+=`<tr style="background:${{ROW[r.attack]||'#26292d'}}"><td>${{data.length-i}}</td><td>${{r.t}}</td><td>${{r.src}}</td><td>${{r.dst}}</td><td><span style="background:${{BDG[r.attack]||'#3a3d42'}};color:#fff;padding:2px 8px;border-radius:3px;font-weight:600;font-size:12px">${{r.attack}}</span></td></tr>`;}}
            t.innerHTML=h;}}
            let ty={{}},mins={{}};
            data.forEach(r=>{{ty[r.attack]=(ty[r.attack]||0)+1;let t=r.t.substring(0,5);mins[t]=(mins[t]||0)+1;}});
            let total=Object.values(ty).reduce((a,b)=>a+b,0);
            let pLabels=Object.keys(ty).map(l=>`${{l}} (${{Math.round(ty[l]/total*1000)/10}}%)`);
            let pVals=Object.values(ty);let pColors=Object.keys(ty).map(l=>BDG[l]||'#3a3d42');
            if(window.c0){{window.c0.data.labels=pLabels;window.c0.data.datasets[0].data=pVals;window.c0.data.datasets[0].backgroundColor=pColors;window.c0.update();}}
            let mLabels=Object.keys(mins).sort();let mVals=mLabels.map(k=>mins[k]);
            if(window.c1){{window.c1.data.labels=mLabels;window.c1.data.datasets[0].data=mVals;window.c1.update();}}
        }});
        fetch('/api/logs').then(r=>r.text()).then(txt=>{{const p=document.getElementById('console-pre');if(p)p.innerText=txt;}});
    }},2000);</script>"""
    return render_template_string(TPL,b=b,p="a",r=False)

@app.route("/")
def models():
    import joblib
    df=pd.read_csv(MD+"/evaluation_summary.csv"); best=df.loc[df["Test F1"].idxmax()]
    b=f"<h1 class='text-center'>Models</h1><p class='text-center'>Best: <b class='text-success'>{best['Model']} ({best['Test F1']*100:.2f}%)</b> | Avg Acc: {df['Test Acc'].mean()*100:.2f}% | Avg ROC: {df['ROC-AUC'].mean()*100:.2f}%</p>"
    ds=[{"label":m,"data":[round(x*100,2) for x in df[m]],"backgroundColor":C[i]} for i,m in enumerate(["Test F1","Test Acc","ROC-AUC"])]
    b+=chart("c2",df["Model"],ds,ymax=105,legend=True)
    rep=pd.read_csv(MD+"/"+best["Model"]+"_report.csv",index_col=0).rename(columns={"precision":"Prec","recall":"Rec","f1-score":"F1"})
    b+=f"<h1 class='text-center'>Per-Class - {best['Model']}</h1>"+(rep[["Prec","Rec","F1"]]*100).round(2).to_html(border=0)
    return render_template_string(TPL,b=b,p="m",r=False)

@app.route("/compare")
def compare():
    import joblib
    df=pd.read_csv(MD+"/evaluation_summary.csv")
    b="<h1 class='text-center'>Compare</h1>"+(df.set_index("Model")*100).round(2).to_html(border=0)
    try:
        tt=pd.Series(joblib.load(MD+"/train_time.pkl")).rename(index={"Stacking":"Voting"})
        b+=chart("c3",tt.index,[{"label":"seconds","data":[round(float(x),1) for x in tt.values],"backgroundColor":"#4da3ff"}])
    except: pass
    return render_template_string(TPL,b=b,p="c",r=False)

@app.route("/help")
def runbook():
    b="<h1 class='text-center'>System Runbook</h1>"
    b+="<div class='box text-center'><b>Methodology Note:</b> While this project utilizes automated Python/Scapy scripts for seamless, one-click demonstration and ease of use, all attacks are designed to mimic real-world scenarios. The system is fully compatible with standard industry tools and can be executed using a Kali Linux VM.</div>"
    b+="<div class='box'><b>How to use Kali Linux VM:</b><br>1. Install VirtualBox/VMware and load the Kali Linux ISO.<br>2. Set the VM Network Adapter to <b>Bridged Mode</b> (so it shares your physical network).<br>3. Boot Kali, open the terminal, and run the industry-standard commands listed below against your target IP. The sniffer will detect them exactly as it does the Python scripts.</div>"
    b+="<div class='box'><b>Live Mode (Python):</b> Requires Admin, Npcap, and trained models. Run <code>start_live.bat</code>.<br><b>Kali VM Mode:</b> For industry-standard attacks using Kali Linux. Run <code>start_with_kali.bat</code> to start monitoring and view attack commands.<br><b>Demo Mode:</b> No network needed. Run <code>start_demo.bat</code> to replay a guaranteed capture.</div>"
    b+="<h1 class='text-center'>Attack Reference</h1><table><tr><th>Attack</th><th>Python (Our Method)</th><th>Kali Linux (Industry Standard)</th><th>Wireshark Filter</th></tr>"
    ATT=[
 ("Benign","benign background sessions in demo.pcap","ping -c 5 10.20.20.10<br>curl http://10.20.20.10/<br>ssh 10.20.20.10","icmp or tcp.dstport==80 or tcp.dstport==22"),
 ("PortScan","send([IP(dst=T)/TCP(dport=p,flags='S') for p in range(1,600)])","nmap 10.20.20.10","tcp.flags.syn==1 and tcp.flags.ack==0"),
 ("DoS","send([IP(dst=T)/TCP(sport=1234,dport=80,flags='S') for _ in range(3000)])","hping3 --flood 10.20.20.10","tcp.flags.syn==1 and tcp.dstport==80"),
 ("DDoS","5 spoofed sources flooding port 80","hping3 --flood 10.20.20.10","ip.dst==10.20.20.10"),
 ("BruteForce","send(IP(dst=T)/TCP(sport=46000+i,dport=22,flags='S')/Raw(b'x'),count=3)","hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.20.20.10","tcp.dstport==22"),
 ("Web Attack","send(IP(dst=T)/TCP(sport=47000+i,dport=80,flags='PA')/Raw(b\"GET /id=1' OR '1'='1\"),count=2)","nikto -h http://10.20.20.10","tcp.dstport==80"),
 ("Bot","beacon every 2s in a loop","nc -lvkp 9001<br>sudo hping3 -c 25 -i u500000 -S -p 9001 10.20.20.10","tcp.flags.syn==1 and tcp.dstport==9001"),
 ("Infiltration","send([IP(dst=T)/TCP(sport=49000,dport=443,flags='PA')/Raw(b'B'*1300) for _ in range(400)])","nc -lvkp 9001 &gt; /dev/null<br>nc -q 1 10.20.20.10 9001 &lt; ~/test-10mb.bin","tcp.dstport==9001"),
]
    for k,p,kali,f in ATT: b+=f"<tr style='background:{ROW.get(k,'#26292d')}'><td>{chip(k)}</td><td>{p}</td><td>{kali}</td><td>{f}</td></tr>"
    b+="</table>"
    return render_template_string(TPL,b=b,p="h",r=False)

@app.route("/clear")
def clear():
    for f in (MD+"/alerts.json",MD+"/live.log"):
        try: open(f,"w").close()
        except: pass
    return '<script>location.href="/alerts"</script>'

if __name__=="__main__":
    print("open http://127.0.0.1:5000")
    app.run()