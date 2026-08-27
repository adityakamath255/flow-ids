# flow-ids

An experimental network intrusion detection pipeline for live IPv4 traffic and pcap replays. It groups TCP and UDP packets into bidirectional flows, extracts CICFlowMeter-style statistics, assigns XGBoost probabilities to five traffic classes, and records the results in SQLite for a Streamlit dashboard.

The five classes are `BENIGN`, `BRUTE-FORCE`, `DDOS`, `DOS`, and `RECON`. The detector uses flow metadata and timing statistics. It does not inspect payload contents, block traffic, or send alerts.

## Pipeline

```text
live interface or pcap
-> Scapy AsyncSniffer
-> one-packet queue
-> FlowTable
-> completed Flow
-> XGBoost probabilities
-> SQLite
-> Streamlit dashboard
```

The `cicflowmeter` package began as a vendored copy of [hieulw/cicflowmeter](https://github.com/hieulw/cicflowmeter). Its [`open_flows`](cicflowmeter/capture.py) function starts Scapy's sniffer and returns an iterator of completed flows. The sniffer callback only places packets in a queue with capacity one. The consuming thread updates the flow table and extracts features, so flow state is never accessed from the capture thread.

A flow key contains the transport, source and destination addresses, and ports. Reverse packets join the same flow. TCP teardown, reset, a 120-second duration, 240 seconds without an update, the end of a pcap, or shutdown can complete a flow. Each result contains the original key, capture time, and numeric features.

[`Classifier`](classifier.py) reads the feature order and class names from the XGBoost model. It returns every class probability rather than only the winning label. [`flow_database.py`](flow_database.py) stores the flow identity, features, and probabilities; raw packets are not written. The `classified_flow` SQLite view derives the label and confidence when queried.

Each detector run creates a session row with its source and start and end times. The database uses WAL mode. [`dashboard.py`](dashboard.py) opens it read-only, refreshes once per second, and displays the latest 2,000 flows, label counts, attack rate, throughput, and capture sessions.

## Setup

Requires Python 3.10 or newer and [uv](https://docs.astral.sh/uv/). The checked-in `.python-version` currently selects Python 3.14.

```bash
uv sync
```

Models and training data are excluded from the repository. Before running the detector, train `models/model.json` as described below or pass another compatible model with `--model`.

Pcap replay needs no packet-capture privileges. On Linux, live capture needs raw-network capabilities. To avoid granting those capabilities to the shared system interpreter, replace the virtual environment's interpreter symlink with a private copy and grant capabilities to that copy:

```bash
cp --remove-destination "$(readlink -f .venv/bin/python3)" .venv/bin/python3
sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python3
```

Every program launched through that copied interpreter receives those capabilities. Keep it inside this virtual environment and remove the environment when it is no longer needed.

## Running the detector

Replay a capture:

```bash
uv run python3 main.py --pcap capture.pcap
```

Capture an interface:

```bash
uv run python3 main.py --interface eth0
```

Both commands write to `flows.db` by default. After the database exists, start the dashboard in a second terminal:

```bash
uv run streamlit run dashboard.py
```

Use the same non-default database in both processes when needed:

```bash
uv run python3 main.py --pcap capture.pcap --db results.db
uv run streamlit run dashboard.py -- --db results.db
```

Detector options:

```text
-i, --interface     live capture interface, mutually exclusive with --pcap
-p, --pcap          pcap file to replay, mutually exclusive with --interface
-m, --model         model path, default: models/model.json
-d, --db            SQLite path, default: flows.db
```

Press Ctrl+C to stop live capture. Pending flows are completed before the capture session closes.

## Exporting flow features

The vendored flow meter can write a CSV without a trained model or database:

```bash
uv run python3 -m cicflowmeter.cli --file capture.pcap flows.csv
```

It also accepts a live interface or a directory of `.pcap` and `.pcapng` files. `--fields` selects CSV columns, and `--merge` combines a directory into one output file.

## Training

Training uses the [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) machine-learning CSV files. Place them in `training-data/MachineLearningCVE/`, then run:

```bash
uv run python3 train.py
```

[`train.py`](train.py) strips column whitespace, maps dataset names to extractor feature names, removes duplicate rows, discards unsupported labels, drops configured topology, duplicate, and unpopulated columns, and changes infinite values to missing values. It makes a stratified 80/20 split and trains XGBoost with balanced sample weights.

The script prints classification reports for the training and test splits, then atomically writes `models/model.json`. The model stores its feature order and ordered class names, so inference does not depend on a separate encoder or metadata file.

CIC-IDS2017 contains synthetic traffic recorded in 2017. Its test split measures performance on that dataset, not on current production traffic.

## Tests

```bash
uv run python3 -m unittest discover -s tests -v
```

The tests cover flow identity and termination, feature values, capture shutdown, CSV output, the pcap-to-SQLite path, database constraints, training preparation, and model save/load behavior.

## Limitations

- Only IPv4 TCP and UDP packets are processed.
- The model can only choose among its five configured classes. Unseen attacks can still receive a confident known label.
- Live capture can lose packets if flow processing cannot keep up with the network source.
- Features accumulate until a flow completes, so a high-volume flow can retain many packet records for up to its timeout.
- The dashboard reports classifications but provides no authentication, notification, or response mechanism.
- The feature extractor is tested against representative CICFlowMeter values, not every possible flow shape in CIC-IDS2017.

## License

[MIT](LICENSE)
