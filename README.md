# flow-ids

Network intrusion detection system. Sniffs live traffic or replays pcap files, extracts flow-level features, and classifies each flow with a trained XGBoost model. Results stream to a real-time web dashboard and are logged as JSONL.

## Architecture

```
packets          Scapy AsyncSniffer
   │
   ▼
flows            FlowSession (modified CICFlowMeter)
   │             extracts ~80 features per flow
   ▼
flow queue
   │
   ▼
main thread ───→ Classifier (XGBoost)
   │
   ├───→ Dashboard (FastAPI + SSE)
   │
   └───→ JSONL log
```

Scapy captures packets and a modified [CICFlowMeter](https://github.com/hieulw/cicflowmeter) assembles them into bidirectional network flows with statistical features (packet lengths, inter-arrival times, flag counts, byte rates). The main thread pulls flows from the queue, classifies each one, and pushes results to the dashboard and log file.

Two threads: Scapy's sniffer and a daemon thread running uvicorn for the dashboard. Classification and logging happen on the main thread.

## Model

Trained on the [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset. The training pipeline removes duplicates, maps dataset columns to CICFlowMeter feature names, groups 15 attack labels into 5 classes, and trains an XGBoost classifier.

Per-class results on the test set (20% stratified split, 504k samples):

| Class | Precision | Recall | F1 |
|---|---|---|---|
| BENIGN | 99.97% | 99.93% | 99.95% |
| DDOS | 99.99% | 100.00% | 99.99% |
| DOS | 99.81% | 99.95% | 99.88% |
| BRUTE-FORCE | 99.89% | 99.84% | 99.86% |
| RECON | 98.79% | 99.42% | 99.11% |

CIC-IDS2017 is synthetic traffic generated in a controlled environment. Real-world performance will differ.

## Setup

```bash
git clone https://github.com/adityakamath255/flow-ids.git
cd flow-ids
python3 -m venv --copies .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The `--copies` flag is required. It copies the Python binary into the venv instead of symlinking it, which is needed for the next step.

For live capture, the venv Python binary needs packet capture capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3
```

This is not needed for pcap replay.

## Usage

Live capture:

```bash
python3 main.py -i <interface>
```

Pcap replay:

```bash
python3 main.py -p <file.pcap>
```

The dashboard runs at `http://localhost:8000`. Past sessions can be viewed from the session dropdown.

Options:

```
-i, --interface       Network interface for live capture
-p, --pcap            Path to pcap file for replay
-l, --log-dir         Log output directory (default: logs/)
-e, --expired_update  Flow expiry interval in seconds (default: 10)
-P, --port            Dashboard port (default: 8000)
```

## Retraining

Place the CIC-IDS2017 CSV files in `training-data/MachineLearningCVE/`, then:

```bash
python3 train.py
```

This writes `model.json` and `encoder.pkl` to `models/`. Training configuration (feature mapping, class grouping, XGBoost hyperparameters) is at the top of `train.py`.

## Stack

Scapy, XGBoost, scikit-learn, FastAPI, uvicorn, SSE, Chart.js

Requires Python 3.10+.
