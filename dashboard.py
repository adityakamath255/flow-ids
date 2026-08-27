import argparse
import sqlite3
from collections.abc import Sequence
from pathlib import Path

import pandas as pd
import streamlit as st

from flow_database import RECENT_FLOWS_QUERY, SESSIONS_QUERY

WINDOW = 2000
BENIGN = "BENIGN"


def is_attack(label):
    return label != BENIGN


@st.cache_resource
def connect(db_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(
        f"file:{db_path}?mode=ro",
        uri=True,
        check_same_thread=False,
    )


def recent_flows(db_path: Path) -> pd.DataFrame:
    df = pd.read_sql_query(
        RECENT_FLOWS_QUERY,
        connect(db_path),
        params=[WINDOW],
    )
    df["captured_at"] = pd.to_datetime(df["captured_at"], unit="s")
    return df


def throughput(df: pd.DataFrame) -> float:
    span = (df["captured_at"].max() - df["captured_at"].min()).total_seconds()
    return len(df) / span if span else 0.0


def per_second(df: pd.DataFrame) -> pd.DataFrame:
    attack = is_attack(df["label"])
    seconds = df["captured_at"].dt.floor("s")
    counts = pd.DataFrame({"second": seconds, "attacks": attack.astype(int)})
    grouped = counts.groupby("second")["attacks"].agg(["count", "sum"])
    return pd.DataFrame(
        {
            "benign": grouped["count"] - grouped["sum"],
            "attacks": grouped["sum"],
        }
    )


def sessions(db_path: Path) -> pd.DataFrame:
    df = pd.read_sql_query(
        SESSIONS_QUERY,
        connect(db_path),
        params=[BENIGN],
    )
    fmt = "%Y-%m-%d %H:%M:%S"
    df["started_at"] = pd.to_datetime(df["started_at"], unit="s").dt.strftime(
        fmt
    )
    ended = pd.to_datetime(df["ended_at"], unit="s").dt.strftime(fmt)
    df["ended_at"] = ended.fillna("running")
    return df


def highlight_attacks(row: pd.Series) -> list[str]:
    attacked = is_attack(row["label"])
    style = "background-color: rgba(220,53,69,0.18)" if attacked else ""
    return [style] * len(row)


@st.fragment(run_every="1s")
def view(db_path: Path) -> None:
    df = recent_flows(db_path)
    if df.empty:
        st.caption("waiting for flows...")
        return

    attacks = int(is_attack(df["label"]).sum())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("flows (recent)", len(df))
    c2.metric("non-benign", attacks)
    c3.metric("attack rate", f"{attacks / len(df):.1%}")
    c4.metric("flows/sec", f"{throughput(df):.0f}")

    left, right = st.columns(2)
    left.subheader("label distribution")
    left.bar_chart(df["label"].value_counts())
    right.subheader("flows over time")
    right.area_chart(per_second(df))

    st.subheader("recent flows")
    st.dataframe(
        df.style.apply(highlight_attacks, axis=1),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("sessions")
    st.dataframe(sessions(db_path), use_container_width=True, hide_index=True)


def parse_args(argv: Sequence[str] | None = None) -> Path:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--db",
        default=Path("flows.db"),
        type=Path,
        help="SQLite database path",
    )
    return parser.parse_args(argv).db


def main() -> None:
    st.set_page_config(page_title="flow-ids", layout="wide")
    st.title("flow-ids")
    view(parse_args())


if __name__ == "__main__":
    main()
