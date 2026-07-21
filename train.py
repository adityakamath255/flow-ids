from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import cast

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight

from model_artifacts import ModelArtifacts

HERE = Path(__file__).resolve().parent
DATASET_DIR = HERE / "training-data/MachineLearningCVE"
OUTPUT_DIR = HERE / "models"
RANDOM_STATE = 42
TEST_SIZE = 0.2

DROP_FEATURES = [
    # host/topology fingerprints
    "dst_port",
    "init_fwd_win_byts",
    "init_bwd_win_byts",
    # exact duplicate of fwd_header_len in the source CSVs
    "fwd_header_len.1",
    # constant across the dataset (bulk counters never populated)
    "bwd_psh_flags",
    "bwd_urg_flags",
    "fwd_byts_b_avg",
    "fwd_pkts_b_avg",
    "fwd_blk_rate_avg",
    "bwd_byts_b_avg",
    "bwd_pkts_b_avg",
    "bwd_blk_rate_avg",
]

# drop web attacks and advanced exploits (absent classes drop out via the map)
CLASS_GROUPS = {
    "BENIGN": ["BENIGN"],
    "DDOS": ["DDOS"],
    "DOS": ["DOS HULK", "DOS GOLDENEYE", "DOS SLOWLORIS", "DOS SLOWHTTPTEST"],
    "RECON": ["PORTSCAN", "BOT"],
    "BRUTE-FORCE": ["SSH-PATATOR", "FTP-PATATOR"],
}

XGBOOST_PARAMS = {
    "n_estimators": 100,
    "max_depth": 8,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
}

FEATURE_MAPPING: dict[str, str] = {
    "Destination Port": "dst_port",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",
    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    "Total Length of Bwd Packets": "totlen_bwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Flow Bytes/s": "flow_byts_s",
    "Flow Packets/s": "flow_pkts_s",
    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",
    "Average Packet Size": "pkt_size_avg",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "FIN Flag Count": "fin_flag_cnt",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",
    "ECE Flag Count": "ece_flag_cnt",
    "Fwd Header Length": "fwd_header_len",
    "Fwd Header Length.1": "fwd_header_len.1",
    "Bwd Header Length": "bwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s",
    "Bwd Packets/s": "bwd_pkts_s",
    "Down/Up Ratio": "down_up_ratio",
    "CWE Flag Count": "cwr_flag_count",
    "Avg Fwd Segment Size": "fwd_seg_size_avg",
    "Avg Bwd Segment Size": "bwd_seg_size_avg",
    "Fwd Avg Bytes/Bulk": "fwd_byts_b_avg",
    "Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
    "Fwd Avg Bulk Rate": "fwd_blk_rate_avg",
    "Bwd Avg Bytes/Bulk": "bwd_byts_b_avg",
    "Bwd Avg Packets/Bulk": "bwd_pkts_b_avg",
    "Bwd Avg Bulk Rate": "bwd_blk_rate_avg",
    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Subflow Fwd Bytes": "subflow_fwd_byts",
    "Subflow Bwd Packets": "subflow_bwd_pkts",
    "Subflow Bwd Bytes": "subflow_bwd_byts",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",
    "act_data_pkt_fwd": "fwd_act_data_pkts",
    "min_seg_size_forward": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}


def load_data() -> pd.DataFrame:
    files = sorted(DATASET_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {DATASET_DIR}")
    frames = (
        pd.read_csv(f, encoding="utf-8", encoding_errors="replace")
        for f in files
    )
    df = pd.concat(frames, ignore_index=True)
    df.columns = df.columns.str.strip()
    return df.rename(columns=FEATURE_MAPPING)


def prepare(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    df = df.drop_duplicates()

    label_to_group = {
        cls: group
        for group, classes in CLASS_GROUPS.items()
        for cls in classes
    }
    y = df["Label"].str.strip().str.upper().map(label_to_group)
    grouped = y.notna()

    X = (
        df.loc[grouped]
        .drop(columns=["Label", *DROP_FEATURES], errors="ignore")
        .replace([np.inf, -np.inf], np.nan)
    )
    return X, y[grouped]


def train(X: pd.DataFrame, y: np.ndarray) -> xgb.XGBClassifier:
    model = xgb.XGBClassifier(**XGBOOST_PARAMS)
    model.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    return model


def evaluate(
    model: xgb.XGBClassifier,
    splits: list[tuple[str, pd.DataFrame, np.ndarray]],
    labels: Sequence[str],
) -> dict:
    metrics: dict = {"labels": list(labels)}
    label_ids = np.arange(len(labels))
    for name, X, y in splits:
        pred = model.predict(X)
        print(f"\n== {name} ==")
        print(
            classification_report(
                y,
                pred,
                labels=label_ids,
                target_names=labels,
                digits=4,
            )
        )
        metrics[name] = {
            "report": classification_report(
                y,
                pred,
                labels=label_ids,
                target_names=labels,
                output_dict=True,
            ),
            "confusion_matrix": confusion_matrix(
                y, pred, labels=label_ids
            ).tolist(),
        }
    return metrics


def main() -> None:
    def log(msg: str) -> None:
        print(f"[{datetime.now():%H:%M:%S}] {msg}")

    log("Loading data...")
    df = load_data()

    log("Preparing features...")
    X, y = prepare(df)
    log(f"{len(X)} flows, {X.shape[1]} features, {y.nunique()} classes")

    X_train, X_test, y_train, y_test = cast(
        tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series],
        train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y,
        ),
    )

    encoder = LabelEncoder().fit(y)
    classes = cast(np.ndarray, encoder.classes_)
    y_train_enc = encoder.transform(y_train)
    y_test_enc = encoder.transform(y_test)

    log("Training...")
    model = train(X_train, y_train_enc)

    log("Evaluating...")
    metrics = evaluate(
        model,
        [("train", X_train, y_train_enc), ("test", X_test, y_test_enc)],
        [str(label) for label in classes],
    )

    log("Saving artifacts...")
    ModelArtifacts(OUTPUT_DIR).save(model, encoder, metrics)
    log("Done.")


if __name__ == "__main__":
    main()
