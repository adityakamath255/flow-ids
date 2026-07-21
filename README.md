# flow-ids

Network intrusion detection system. It sniffs live traffic or replays pcap
files, extracts flow-level features, and classifies each flow with a trained
XGBoost model. Results go to SQLite and a Streamlit dashboard reads them.

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

Scapy captures packets and a vendored copy of
[CICFlowMeter](https://github.com/hieulw/cicflowmeter) (in `cicflowmeter/`)
assembles them into bidirectional network flows with statistical features.
Its `open_flows()` API owns the sniffer, session, and queue. The main thread
iterates over completed flows, classifies them, and writes the results to
SQLite.

The dashboard is a separate Streamlit process with a read-only connection to
the same database. WAL mode lets the reader and writer proceed concurrently.

## Model

Training uses the
[CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) dataset. The
pipeline removes duplicates, maps dataset columns to CICFlowMeter feature
names, groups attack labels into five classes, and trains an XGBoost
classifier. The saved artifact contains the evaluation for its model.

CIC-IDS2017 is synthetic traffic generated in a controlled environment.
Real-world performance will differ.

## Setup

Install [uv](https://docs.astral.sh/uv/), then:

```bash
git clone https://github.com/adityakamath255/flow-ids.git
cd flow-ids
uv sync
```

`uv sync` creates `.venv/` and installs the dependency versions in `uv.lock`
and the Python version in `.python-version`. Run commands with `uv run` or
activate the venv with `source .venv/bin/activate`.

For live capture, the venv Python binary needs packet capture capabilities.
`uv` symlinks the venv interpreter to the base Python. Replace that symlink
with a private copy, then grant the capability to the copy:

```bash
cp --remove-destination "$(readlink -f .venv/bin/python3)" .venv/bin/python3
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3
```

Neither step is needed for pcap replay.

## Usage

Live capture:

```bash
uv run python3 main.py -i <interface>
```

Pcap replay:

```bash
uv run python3 main.py -p <file.pcap>
```

Either command writes classified flows to `flows.db`. Start the dashboard in
a second terminal:

```bash
uv run streamlit run dashboard.py
```

Options:

```
-i, --interface     Network interface for live capture (mutually exclusive with -p)
-p, --pcap          Path to pcap file for replay (mutually exclusive with -i)
-m, --model-dir     Model directory (default: models/)
-d, --db            SQLite output path (default: flows.db)
```

## Retraining

Place the CIC-IDS2017 CSV files in `training-data/MachineLearningCVE/`, then:

```bash
uv run python3 train.py
```

This atomically writes `models/artifacts.zip`. The archive contains the model,
label encoder, and evaluation metrics. Training configuration is in `train.py`;
the CIC-IDS2017 column contract is in `cicflowmeter/schema.py`.

## Tests

```bash
uv run python3 -m unittest discover -s tests -v
```

## Stack

Scapy, XGBoost, scikit-learn, Streamlit, pandas, SQLite

Requires Python 3.10+.
