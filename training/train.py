import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import xgboost as xgb
from sklearn.metrics import classification_report
from pathlib import Path
import joblib
from datetime import datetime

from .config import (
    DATASET_DIR,
    OUTPUT_DIR,
    FEATURE_MAPPING,
    CORRELATION_DROP,
    ZERO_VARIANCE_DROP,
    CLASS_GROUPS,
    TEST_SIZE,
    RANDOM_STATE,
    XGBOOST_PARAMS
)


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
        target_names=encoder.classes_
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
