import os, json
import pandas as pd
import matplotlib.pyplot as plt

os.chdir(os.path.dirname(os.path.abspath(__file__)))

rows = [json.loads(l) for l in open("Models/alerts.json", encoding="utf-8") if l.strip()]
s = pd.Series([r["attack"] for r in rows]).value_counts()
s = s.reindex(["BruteForce", "Web Attack", "DDoS", "PortScan", "DoS", "Bot", "Infiltration"]).fillna(0)

plt.figure(figsize=(9, 5))
s.plot(kind="bar", color="#8f2d2d")
plt.ylabel("Alerts")
plt.title("Observed demo replay alerts by class")
plt.tight_layout()
plt.savefig("demo_alerts.png", dpi=300)
print("saved demo_alerts.png")