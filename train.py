import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import xgboost as xgb
from sklearn.metrics import classification_report
from pathlib import Path
import joblib
from datetime import datetime

HERE = Path(__file__).resolve().parent
DATASET_DIR = HERE / "training-data/MachineLearningCVE"
OUTPUT_DIR = HERE / "models"
RANDOM_STATE = 42
TEST_SIZE = 0.2

CORRELATION_DROP = [
    'subflow_fwd_pkts', 'subflow_fwd_byts', 'subflow_bwd_pkts', 'subflow_bwd_byts',
    'fwd_seg_size_avg', 'bwd_seg_size_avg', 'fwd_header_len.1',
    'syn_flag_cnt', 'cwr_flag_count', 'ece_flag_cnt',
    'tot_bwd_pkts', 'fwd_iat_tot', 'bwd_iat_tot',
    'fwd_iat_min', 'bwd_iat_min', 'fwd_iat_mean', 'bwd_iat_mean', 'fwd_iat_max',
    'idle_max', 'idle_min', 'fwd_pkts_s', 'pkt_size_avg'
]

ZERO_VARIANCE_DROP = [
    'bwd_psh_flags', 'bwd_urg_flags',
    'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'fwd_blk_rate_avg',
    'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'bwd_blk_rate_avg'
]

# drop web attacks and advanced exploits
CLASS_GROUPS = {
    "BENIGN": ["BENIGN"],
    "DDOS": ["DDOS"],
    "DOS": ["DOS HULK", "DOS GOLDENEYE", "DOS SLOWLORIS", "DOS SLOWHTTPTEST"],
    "RECON": ["PORTSCAN", "BOT"],
    "BRUTE-FORCE": ["SSH-PATATOR", "FTP-PATATOR"]
}

XGBOOST_PARAMS = {
    'n_estimators': 100,
    'max_depth': 8,
    'learning_rate': 0.1,
    'objective': 'multi:softprob',
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'random_state': RANDOM_STATE,
    'n_jobs': -1,
    'eval_metric': 'mlogloss'
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


def load_data():
    csv_files = DATASET_DIR.glob("*.csv")

    dfs = (
        pd.read_csv(f, encoding="utf-8", encoding_errors="replace")
        for f in csv_files
        if f != "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
        # mostly duplicate data, based on the lycos analysis
    )

    result = pd.concat(dfs, ignore_index=True)
    result.columns = result.columns.str.strip()
    return result


def clean_data(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    df = (
        df
        .drop_duplicates()
        .rename(columns=FEATURE_MAPPING)
    )

    X = (
        df
        .drop(columns=["Label"])
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0)
    )

    y = (
        df["Label"]
        .str
        .strip()
        .str
        .upper()
    )

    return X, y


def group_classes(
    X: pd.DataFrame, 
    y: pd.Series
) -> tuple[pd.DataFrame, pd.Series]:
    label_to_group = {
        cls: group
        for group, classes in CLASS_GROUPS.items()
        for cls in classes
    }
    y = y.map(label_to_group).dropna()
    X = X.loc[y.index]
    return X, y


def select_features(X: pd.DataFrame) -> pd.DataFrame:
    return X.drop(
        columns=CORRELATION_DROP + ZERO_VARIANCE_DROP, 
        errors="ignore"
    )


def split_data(
    X: pd.DataFrame, 
    y: pd.Series
) -> list:
    return train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )


def scale_features(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, StandardScaler]:
    scaler = StandardScaler()

    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train),
        columns=X_train.columns
    )

    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test),
        columns=X_test.columns
    )

    return X_train_scaled, X_test_scaled, scaler


def encode_labels(
    y_train: pd.Series,
    y_test: pd.Series
) -> tuple[np.ndarray, np.ndarray, LabelEncoder]:
    encoder = LabelEncoder()
    y_train_encoded = encoder.fit_transform(y_train)
    y_test_encoded = encoder.transform(y_test)

    return y_train_encoded, y_test_encoded, encoder


def train_xgboost(
    X_train: pd.DataFrame,
    y_train: pd.Series,
) -> xgb.XGBClassifier:
    model = xgb.XGBClassifier(**XGBOOST_PARAMS)
    model.fit(X_train, y_train)
    return model


def evaluate_model(
    model: xgb.XGBClassifier,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    encoder: LabelEncoder
):
    y_pred = model.predict(X_test)
    print(classification_report(
        y_test,
        y_pred,
        target_names=encoder.classes_,
        digits=4
    ))


def save_artifacts(
    model: xgb.XGBClassifier,
    scaler: StandardScaler,
    encoder: LabelEncoder,
    output_dir: Path
):
    output_dir.mkdir(parents=True, exist_ok=True)
    model.save_model(output_dir / "model.json")
    joblib.dump(scaler, output_dir / "scaler.pkl")
    joblib.dump(encoder, output_dir / "encoder.pkl")


def main():
    def log(msg: str):
        print(f"[{datetime.now():%H:%M:%S}] {msg}")

    log("Loading data...")
    df = load_data()

    log("Cleaning data...")
    X, y = clean_data(df)

    log("Grouping classes...")
    X, y = group_classes(X, y)

    log("Selecting features...")
    X = select_features(X)

    log("Splitting data...")
    X_train, X_test, y_train, y_test = split_data(X, y)

    log("Scaling data...")
    X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)

    log("Encoding labels...")
    y_train_encoded, y_test_encoded, encoder = encode_labels(y_train, y_test)

    log("Training model...")
    model = train_xgboost(X_train_scaled, y_train_encoded)

    log("Evaluating model...")
    evaluate_model(model, X_test_scaled, y_test_encoded, encoder)

    log("Saving artifacts...")
    save_artifacts(model, scaler, encoder, OUTPUT_DIR)

    log("Pipeline complete!")


if __name__ == "__main__":
    main()
