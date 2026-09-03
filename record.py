#record.py - capture 60s of REAL traffic into demo.pcap; attack during it
from scapy.all import sniff,wrpcap,conf
i=conf.route.route("0.0.0.0")[0]
print("recording 60s on",getattr(i,"description",i),"- ATTACK NOW")
pk=sniff(iface=i,timeout=60)
wrpcap("demo.pcap",pk)
print("saved demo.pcap with",len(pk),"packets")