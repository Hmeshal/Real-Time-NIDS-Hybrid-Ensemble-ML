import pandas as pd
import glob

path = r'Raw Dataset/'
files = glob.glob(path+'*.csv')
output = r'Raw Merged-Dataset/PortScan-DDoS-Bot-Infiltration-WebAttacks-BruteForce-DoS-Bengin-Merged.csv'

data_list = []
for f in files:
    print("Loading files:",f)
    datatmp = pd.read_csv(f, low_memory=False)
    data_list.append(datatmp)

data = pd.concat(data_list, ignore_index=True)

print("Saving merged dataset to:", output)
data.to_csv(output, index=False)

print("Done.")
