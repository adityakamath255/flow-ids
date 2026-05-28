# flow-ids

Network intrusion detection system. Sniffs live traffic or replays pcap files, extracts flow-level features, and classifies each flow with a trained XGBoost model. Results are written to a SQLite database and viewed through a real-time Streamlit dashboard.

## Architecture

```
packets          Scapy AsyncSniffer
   │
   ▼
flows            FlowSession (vendored CICFlowMeter)
   │             extracts ~80 features per flow
   ▼
flow queue
   │
   ▼
main thread ───→ Classifier (XGBoost) ───→ SQLite (flows.db)
                                               │
                                               ▼
                                          Dashboard (Streamlit, read-only)
```

Scapy captures packets and a vendored copy of [CICFlowMeter](https://github.com/hieulw/cicflowmeter) (in `cicflowmeter/`) assembles them into bidirectional network flows with statistical features (packet lengths, inter-arrival times, flag counts, byte rates). The sniffer runs on its own thread and pushes completed flows onto a queue; the main thread pulls each flow, classifies it, and writes the result to a SQLite database.

The dashboard is a separate Streamlit process that reads the same database read-only (the writer uses WAL mode, so reads and writes don't block each other).

## Model

Trained on the [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset. The training pipeline removes duplicates, maps dataset columns to CICFlowMeter feature names, groups attack labels into 5 classes, and trains an XGBoost classifier.

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

Either command writes classified flows to `flows.db`. In a second terminal, start the dashboard:

```bash
streamlit run dashboard.py
```

Options:

```
-i, --interface     Network interface for live capture (mutually exclusive with -p)
-p, --pcap          Path to pcap file for replay (mutually exclusive with -i)
-m, --model-dir     Model directory (default: models/)
-t, --idle-timeout  Expired flow update interval in seconds (default: 10)
-d, --db            SQLite output path (default: flows.db)
```

## Retraining

Place the CIC-IDS2017 CSV files in `training-data/MachineLearningCVE/`, then:

```bash
python3 train.py
```

This writes `model.json` and `encoder.pkl` to `models/`. Training configuration (feature mapping, class grouping, XGBoost hyperparameters) is at the top of `train.py`.

## Stack

Scapy, XGBoost, scikit-learn, Streamlit, pandas, SQLite

Requires Python 3.10+.
</content>
</invoke>
