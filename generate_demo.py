#generate_demo.py - makes demo.pcap with every attack type | run once
from scapy.all import IP,TCP,Raw,wrpcap
import random
random.seed(7)
t=1000.0; pkts=[]; V="10.0.0.10"

def P(src,dst,sp,dp,fl="S",size=60,dt=0.0):
    global t
    t+=dt
    p=IP(src=src,dst=dst)/TCP(sport=sp,dport=dp,flags=fl)/Raw(b"A"*max(size-54,0))
    p.time=t
    return p

for i in range(8):
    s,sp="10.0.0.%d"%(50+i),50000+i
    pkts+=[P(s,V,sp,80,"S",60,dt=0.5),P(V,s,80,sp,"SA",60,dt=0.01),P(s,V,sp,80,"A",54,dt=0.01)]
    for j in range(4):
        pkts+=[P(s,V,sp,80,"PA",random.randint(400,900),dt=0.05),P(V,s,80,sp,"PA",random.randint(500,1400),dt=0.05)]
    pkts+=[P(s,V,sp,80,"FA",60,dt=0.1),P(V,s,80,sp,"FA",60,dt=0.01)]
for port in range(1000,1060): pkts.append(P("10.0.0.5",V,45000,port,"S",60,dt=0.03))
for i in range(500): pkts.append(P("10.0.0.5",V,1234,80,"S",60,dt=0.004))
V2="10.0.0.20"
for src in range(1,6):
    for i in range(300): pkts.append(P("10.0.0.%d"%src,V2,1234,80,"S",60,dt=0.004))
for i in range(30):
    sp=46000+i
    pkts+=[P("10.0.0.5",V,sp,22,"S",60,dt=0.4),P(V,"10.0.0.5",22,sp,"SA",60,dt=0.01),P("10.0.0.5",V,sp,22,"A",60,dt=0.01)]
    for j in range(3):
        pkts+=[P("10.0.0.5",V,sp,22,"PA",120,dt=0.05),P(V,"10.0.0.5",22,sp,"PA",120,dt=0.05)]
    pkts.append(P("10.0.0.5",V,sp,22,"R",60,dt=0.05))
for i in range(15):
    sp=47000+i
    pkts+=[P("10.0.0.6",V,sp,80,"S",60,dt=0.3),P(V,"10.0.0.6",80,sp,"SA",60,dt=0.01),
           P("10.0.0.6",V,sp,80,"PA",700,dt=0.01),P(V,"10.0.0.6",80,sp,"PA",300,dt=0.05),
           P("10.0.0.6",V,sp,80,"FA",60,dt=0.05)]
for i in range(20):
    pkts+=[P("10.0.0.7",V,48000,443,"PA",120,dt=1.0),P(V,"10.0.0.7",443,48000,"PA",120,dt=0.02)]
sp=49000
pkts+=[P("10.0.0.8",V,sp,443,"S",60,dt=0.5),P(V,"10.0.0.8",443,sp,"SA",60,dt=0.01)]
for i in range(200):
    pkts.append(P("10.0.0.8",V,sp,443,"PA",1400,dt=0.05))
    if i%20==0: pkts.append(P(V,"10.0.0.8",443,sp,"A",60,dt=0.01))

wrpcap("demo.pcap",pkts)
print("demo.pcap ready:",len(pkts),"packets")