# Real-Time Network Intrusion Detection System (NIDS)

A real-time Network Intrusion Detection System based on the **CICIDS2017** dataset and machine learning.

The project performs multi-class network traffic classification using **Random Forest, Decision Tree, LightGBM, XGBoost**, and a final **Weighted Soft Voting Ensemble**.

The trained model is integrated with live packet capture, flow-based feature extraction, runtime behavioral rules, and a Flask monitoring dashboard.

---

## Project Overview

The complete project workflow is:

```text
Original CICIDS2017 Dataset
        ↓
      merge.py
        ↓
Merged Dataset
        ↓
      clean.py
        ↓
Cleaned Multi-Class Dataset
        ↓
      train.py
        ↓
Trained ML Models
        ↓
    evaluate.py
        ↓
Model Evaluation
        ↓
     sniffer.py
        ↓
Real-Time Detection
        ↓
      app.py
        ↓
Monitoring Dashboard
```

---

## Target Classes

The project uses **8 traffic classes**:

| ID | Class |
|---:|---|
| 0 | Benign |
| 1 | DDoS |
| 2 | PortScan |
| 3 | Bot |
| 4 | BruteForce |
| 5 | WebAttack |
| 6 | DoS |
| 7 | Infiltration |

---

## Machine Learning Models

The following classifiers are trained and evaluated:

- Random Forest
- Decision Tree
- LightGBM
- XGBoost
- Weighted Soft Voting Ensemble

### Final Voting Ensemble

The final ensemble combines:

```text
Random Forest : LightGBM : XGBoost
      4       :    2     :    1
```

The project uses **Soft Voting**, meaning the final decision is based on weighted class probabilities rather than only the final predicted class from each classifier.

Conceptually:

```text
Final Probability =
(4 × P(RandomForest) + 2 × P(LightGBM) + 1 × P(XGBoost)) / 7
```

Decision Tree is trained and evaluated independently but is not included in the final Voting Ensemble.

---

# Dataset

This project is based on:

**CICIDS2017**  
Canadian Institute for Cybersecurity (CIC)  
University of New Brunswick, Canada

The original CICIDS2017 dataset is composed of multiple CSV files representing different working days and attack scenarios.

Large datasets and pretrained machine-learning models are not stored directly in this GitHub repository.

They are available through the project Kaggle dataset:

## Kaggle Dataset and Pretrained Models

[Download the prepared datasets and pretrained models from Kaggle](https://www.kaggle.com/datasets/meshalalossaimi/cicids2017-nids-dataset-and-models)

The Kaggle package contains:

- Merged CICIDS2017 dataset
- Cleaned multi-class dataset
- Random Forest pipeline
- Decision Tree pipeline
- LightGBM pipeline
- XGBoost pipeline
- Voting Ensemble pipeline
- Supporting model artifacts

---

# Downloaded File Placement

After cloning this repository, download the required files from Kaggle and place them in the following directories.

## Cleaned Dataset

Download:

```text
Cleaned-Multi-Class-Dataset.csv
```

Place it inside:

```text
Dataset/
```

Final path:

```text
Dataset/Cleaned-Multi-Class-Dataset.csv
```

---

## Merged Dataset

Download:

```text
PortScan-DDoS-Bot-Infiltration-WebAttacks-BruteForce-DoS-Bengin-Merged.csv
```

Place it inside:

```text
Raw Merged-Dataset/
```

Final path:

```text
Raw Merged-Dataset/
└── PortScan-DDoS-Bot-Infiltration-WebAttacks-BruteForce-DoS-Bengin-Merged.csv
```

---

## Pretrained Models

Download:

```text
RandomForest_pipeline.pkl
DecisionTree_pipeline.pkl
LightGBM_pipeline.pkl
XGBoost_pipeline.pkl
Voting_pipeline.pkl
```

Place them inside:

```text
Models/
```

Final structure:

```text
Models/
├── RandomForest_pipeline.pkl
├── DecisionTree_pipeline.pkl
├── LightGBM_pipeline.pkl
├── XGBoost_pipeline.pkl
└── Voting_pipeline.pkl
```

---

# Project Structure

```text
Real-Time-NIDS/
│
├── app.py
├── attacks.py
├── checker.py
├── clean.py
├── demo.py
├── evaluate.py
├── generate_demo.py
├── merge.py
├── record.py
├── sniffer.py
├── train.py
│
├── requirements.txt
├── kali_commands.txt
│
├── start_demo.bat
├── start_live_run_as_admin.bat
├── start_with_kali.bat
│
├── Dataset/
│   └── Cleaned-Multi-Class-Dataset.csv
│
├── Raw Dataset/
│   └── Original CICIDS2017 CSV files
│
├── Raw Merged-Dataset/
│   └── PortScan-DDoS-Bot-Infiltration-WebAttacks-BruteForce-DoS-Bengin-Merged.csv
│
└── Models/
    ├── RandomForest_pipeline.pkl
    ├── DecisionTree_pipeline.pkl
    ├── LightGBM_pipeline.pkl
    ├── XGBoost_pipeline.pkl
    ├── Voting_pipeline.pkl
    ├── class_mapping.pkl
    ├── feature_names.pkl
    ├── evaluation_summary.csv
    ├── train_time.pkl
    ├── *_report.csv
    └── confusion_matrices/
```

---

# Installation

## 1. Clone the Repository

```bash
git clone https://github.com/Hmeshal/Real-Time-NIDS.git
cd Real-Time-NIDS
```

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Main dependencies include:

- Flask
- Pandas
- NumPy
- Scapy
- Scikit-learn
- Imbalanced-learn
- XGBoost
- LightGBM
- Joblib
- Matplotlib
- Seaborn

---

# Dataset Preparation

There are two ways to prepare the project.

## Option 1 — Use the Prepared Dataset

Download:

```text
Cleaned-Multi-Class-Dataset.csv
```

from Kaggle and place it inside:

```text
Dataset/
```

Then continue directly to model training or evaluation.

---

## Option 2 — Build the Dataset from the Original CICIDS2017 Files

Place the original CICIDS2017 CSV files inside:

```text
Raw Dataset/
```

Then run:

```bash
python merge.py
```

This creates the merged dataset inside:

```text
Raw Merged-Dataset/
```

Then run:

```bash
python clean.py
```

The cleaned dataset is generated as:

```text
Dataset/Cleaned-Multi-Class-Dataset.csv
```

---

# Data Cleaning

The cleaning stage is implemented in:

```text
clean.py
```

The project performs operations including:

- Removing flows where `Flow Duration = 0`
- Handling positive and negative infinity values
- Removing redundant and duplicate features
- Removing duplicated flow records
- Multi-class label encoding
- Removing unsupported labels

The documented project cleaning stage produced:

| Item | Value |
|---|---:|
| Records before cleaning | 2,830,743 |
| Records after cleaning | 2,520,787 |
| Zero-duration flows removed | 2,867 |
| Duplicate records removed | 307,078 |
| Heartbleed records excluded | 11 |

---

# Feature Engineering

Before training, the project creates additional ratio-based traffic features.

### Forward / Backward Traffic Ratio

```text
Fwd_Bwd_Ratio =
Total Length of Fwd Packets
--------------------------------
Total Length of Bwd Packets + 1
```

### Packet Size Ratio

```text
Packet_Size_Ratio =
Fwd Packet Length Mean
---------------------------
Bwd Packet Length Mean + 1
```

The `+1` prevents division-by-zero errors.

---

# Train / Test Split

The cleaned dataset is divided into:

```text
80% Training
20% Testing
```

using a stratified split.

The stratified split helps preserve the class distribution across both partitions.

---

# Class Imbalance Handling

CICIDS2017 is highly imbalanced.

The project uses model-aware imbalance handling, including:

- Class weights
- Targeted SMOTE oversampling
- Sample weighting

The held-out test dataset is not oversampled.

This ensures that evaluation is performed on the original unseen traffic distribution.

---

# Model Training

Run:

```bash
python train.py
```

The training stage builds:

```text
RandomForest_pipeline.pkl
DecisionTree_pipeline.pkl
LightGBM_pipeline.pkl
XGBoost_pipeline.pkl
Voting_pipeline.pkl
```

and stores the generated artifacts inside:

```text
Models/
```

---

# Model Evaluation

Run:

```bash
python evaluate.py
```

The evaluation pipeline evaluates:

- Random Forest
- Decision Tree
- LightGBM
- XGBoost
- Voting Ensemble

using the same held-out test dataset.

The main metrics are:

- Accuracy
- Macro F1-Score
- ROC-AUC
- Precision
- Recall
- Per-class F1-Score
- Confusion Matrix

---

# Recorded Model Results

| Model | Macro F1 | Accuracy | ROC-AUC |
|---|---:|---:|---:|
| Random Forest | 96.9803% | 99.8578% | 99.9772% |
| Decision Tree | 93.2104% | 99.7659% | 99.2634% |
| LightGBM | 96.8022% | **99.9119%** | 99.9959% |
| XGBoost | 96.6029% | 99.9090% | **99.9979%** |
| Voting Ensemble | **97.4616%** | 99.9058% | 99.9975% |

### Metric Leaders

- **Best Macro F1:** Voting Ensemble — `97.4616%`
- **Best Accuracy:** LightGBM — `99.9119%`
- **Best ROC-AUC:** XGBoost — `99.9979%`

The Voting Ensemble is selected as the main project model because it achieved the strongest class-balanced Macro F1 performance.

---

# Evaluation Outputs

`evaluate.py` generates:

```text
Models/
├── evaluation_summary.csv
├── RandomForest_report.csv
├── DecisionTree_report.csv
├── LightGBM_report.csv
├── XGBoost_report.csv
├── Voting_report.csv
│
└── confusion_matrices/
    ├── RandomForest_cm.png
    ├── DecisionTree_cm.png
    ├── LightGBM_cm.png
    ├── XGBoost_cm.png
    └── Voting_cm.png
```

---

# Real-Time Intrusion Detection

The live IDS is implemented in:

```text
sniffer.py
```

Scapy captures network packets from the selected network interface.

The runtime system:

```text
Network Interface
      ↓
Packet Capture
      ↓
Bidirectional Flow Construction
      ↓
Feature Extraction
      ↓
Feature Alignment
      ↓
Voting Model Prediction
      ↓
Behavioral Detection Rules
      ↓
Final Classification
      ↓
Alert Generation
```

---

## Runtime Model Files

The live detector loads:

```text
Models/Voting_pipeline.pkl
Models/feature_names.pkl
Models/class_mapping.pkl
```

`feature_names.pkl` ensures that live flow features are ordered exactly as expected by the trained model.

`class_mapping.pkl` converts numeric predictions into readable traffic labels.

---

# Runtime Behavioral Detection

In addition to machine-learning inference, the live IDS applies selected behavioral checks.

These include detection logic for:

- DoS
- DDoS
- PortScan
- BruteForce
- WebAttack
- Bot
- Infiltration

The runtime rules use packet counts, ports, TCP flags, flow duration, source distribution, and traffic-volume characteristics.

---

# Running the Live IDS

Live packet capture may require Administrator privileges.

Run:

```bash
python sniffer.py
```

An interface may also be supplied when required.

Example:

```bash
python sniffer.py <interface>
```

---

# Offline Demo Mode

The project also supports offline PCAP replay.

Run:

```bash
python demo.py
```

The demo uses:

```text
demo.pcap
```

This provides a repeatable demonstration without requiring live traffic capture.

---

# Dashboard

The monitoring interface is implemented using Flask.

Run:

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

The dashboard provides:

- Live intrusion alerts
- Attack distribution
- Alerts over time
- Runtime logs
- Model results
- Model comparison
- Runbook information

---

# Alert Storage

Detected attacks are written to:

```text
Models/alerts.json
```

Runtime activity is written to:

```text
Models/live.log
```

Each alert contains information such as:

```text
Attack Type
Source IP
Destination IP
Timestamp
```

---

# Main Source Files

| File | Purpose |
|---|---|
| `merge.py` | Merges the original CICIDS2017 CSV files |
| `clean.py` | Cleans the merged dataset and performs label mapping |
| `checker.py` | Validates the prepared dataset |
| `train.py` | Trains the individual classifiers and Voting Ensemble |
| `evaluate.py` | Evaluates the trained models |
| `sniffer.py` | Live packet capture, flow processing, ML inference, and detection |
| `demo.py` | Offline PCAP replay |
| `generate_demo.py` | Generates demo traffic / PCAP data |
| `app.py` | Flask monitoring dashboard |
| `attacks.py` | Attack-related project functionality |
| `record.py` | Traffic recording functionality |

---

# GitHub and Kaggle Storage Design

Large datasets and trained ML pipelines are separated from the source-code repository.

## GitHub

GitHub contains:

- Python source code
- Requirements
- Launch scripts
- Model reports
- Evaluation summary
- Confusion matrices
- Lightweight supporting artifacts

Repository:

[Real-Time-NIDS GitHub Repository](https://github.com/Hmeshal/Real-Time-NIDS)

---

## Kaggle

Kaggle contains:

- Merged CICIDS2017 dataset
- Cleaned multi-class dataset
- Pretrained Random Forest model
- Pretrained Decision Tree model
- Pretrained LightGBM model
- Pretrained XGBoost model
- Pretrained Voting Ensemble model
- Supporting model artifacts

Dataset:

[CICIDS2017 NIDS Dataset and Models](https://www.kaggle.com/datasets/meshalalossaimi/cicids2017-nids-dataset-and-models)

---

# Quick Start

## Using Pretrained Models

```text
1. Clone GitHub repository
        ↓
2. Install requirements
        ↓
3. Download pretrained models from Kaggle
        ↓
4. Place *.pkl pipelines inside Models/
        ↓
5. Run app.py
        ↓
6. Run sniffer.py or demo.py
```

Commands:

```bash
git clone https://github.com/Hmeshal/Real-Time-NIDS.git
cd Real-Time-NIDS

pip install -r requirements.txt
```

After downloading the pretrained models from Kaggle:

```bash
python app.py
```

and in another terminal:

```bash
python sniffer.py
```

or:

```bash
python demo.py
```

---

# Training from Scratch

```text
Original CICIDS2017
        ↓
Raw Dataset/
        ↓
python merge.py
        ↓
python clean.py
        ↓
python train.py
        ↓
python evaluate.py
```

---

# Technologies

### Machine Learning

- Scikit-learn
- Random Forest
- Decision Tree
- LightGBM
- XGBoost
- Soft Voting Ensemble
- Imbalanced-learn

### Network Processing

- Scapy
- IPv4
- TCP
- UDP
- Flow-based traffic analysis

### Data Processing

- Pandas
- NumPy
- Joblib

### Monitoring

- Flask
- Bootstrap
- Chart.js

---

# Graduation Project

## Real-Time Network Intrusion Detection System Using Hybrid Ensemble Machine Learning

A machine-learning-based approach for detecting malicious network traffic using the CICIDS2017 dataset.

---

# Project Team

- Meshal Hussain Alossaimi
- Abdulmajeed Marzouq Alotaibi
- Abdullah Saad Alkulaib
- Anas Jaber Alasiri
- Nasser Raed Alsawegh

### Supervisor

**Dr. Mohammed AlMaddah**

---

# Dataset Attribution

This project uses the **CICIDS2017** dataset developed by:

**Canadian Institute for Cybersecurity (CIC)**  
**University of New Brunswick, Canada**

The project contribution includes dataset merging, preprocessing, multi-class label mapping, machine-learning training and evaluation, ensemble construction, and integration into a real-time Network Intrusion Detection System.
