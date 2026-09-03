# checker.py (Read-only – safe to run anytime)
import pandas as pd
import numpy as np

data = pd.read_csv(r'./Dataset/Cleaned-Multi-Class-Dataset.csv')

infinity = np.isinf(data.select_dtypes(include=[np.number])).sum().sum()
print("Infinity values existing in the dataset:", infinity)

nan = data.isnull().sum().sum()
print("NaN values existing in the dataset:", nan)

duplicates = data.duplicated().sum()
print("Duplicate rows existing in the dataset:", duplicates)

print("Total columns:", len(data.columns))
print("Feature columns:", len(data.columns) - 1)
print("Class distribution:")
print(data['Label'].value_counts().sort_index())