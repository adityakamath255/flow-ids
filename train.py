from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import cast

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight

from cicflowmeter.schema import CIC_IDS_2017_COLUMNS
from classifier import Classifier

HERE = Path(__file__).resolve().parent
DATASET_DIR = HERE / "training-data/MachineLearningCVE"
MODEL_PATH = HERE / "models/model.json"
RANDOM_STATE = 42
TEST_SIZE = 0.2

TOPOLOGY_FEATURES = (
    "dst_port",
    "init_fwd_win_byts",
    "init_bwd_win_byts",
)
DUPLICATE_FEATURES = ("fwd_header_len.1",)
UNPOPULATED_FEATURES = (
    "bwd_psh_flags",
    "bwd_urg_flags",
    "fwd_byts_b_avg",
    "fwd_pkts_b_avg",
    "fwd_blk_rate_avg",
    "bwd_byts_b_avg",
    "bwd_pkts_b_avg",
    "bwd_blk_rate_avg",
)
DROP_FEATURES = (
    *TOPOLOGY_FEATURES,
    *DUPLICATE_FEATURES,
    *UNPOPULATED_FEATURES,
)

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
    return df.rename(columns=CIC_IDS_2017_COLUMNS)


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
        .drop(columns=["Label", *DROP_FEATURES])
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
    classes: Sequence[str],
) -> None:
    label_ids = np.arange(len(classes))
    for name, X, y in splits:
        pred = model.predict(X)
        print(f"\n== {name} ==")
        print(
            classification_report(
                y,
                pred,
                labels=label_ids,
                target_names=classes,
                digits=4,
            )
        )


def main() -> None:
    def log(msg: str) -> None:
        print(f"[{datetime.now():%H:%M:%S}] {msg}")

    log("Loading data...")
    df = load_data()

    log("Preparing features...")
    X, y = prepare(df)
    log(f"{len(X)} flows, {X.shape[1]} features, {y.nunique()} classes")

    encoder = LabelEncoder().fit(y)
    classes = tuple(str(label) for label in encoder.classes_)
    encoded = encoder.transform(y)
    X_train, X_test, y_train, y_test = cast(
        tuple[pd.DataFrame, pd.DataFrame, np.ndarray, np.ndarray],
        train_test_split(
            X,
            encoded,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=encoded,
        ),
    )

    log("Training...")
    model = train(X_train, y_train)

    log("Evaluating...")
    evaluate(
        model,
        [("train", X_train, y_train), ("test", X_test, y_test)],
        classes,
    )

    log("Saving model...")
    Classifier(model, classes).save(MODEL_PATH)
    log("Done.")


if __name__ == "__main__":
    main()
