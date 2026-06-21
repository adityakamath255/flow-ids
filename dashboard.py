import sqlite3

import pandas as pd
import streamlit as st

DB_PATH = "flows.db"
WINDOW = 2000
BENIGN = "BENIGN"


def is_attack(label):
    return label != BENIGN


@st.cache_resource
def connect() -> sqlite3.Connection:
    return sqlite3.connect(
        f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False
    )


def recent_flows() -> pd.DataFrame:
    df = pd.read_sql_query(
        "SELECT recorded_at, src_ip, dst_ip, dst_port, protocol, label, "
        f"confidence FROM classified_flow ORDER BY recorded_at DESC LIMIT {WINDOW}",
        connect(),
    )
    df["recorded_at"] = pd.to_datetime(df["recorded_at"], unit="s")
    return df


def throughput(df: pd.DataFrame) -> float:
    span = (df["recorded_at"].max() - df["recorded_at"].min()).total_seconds()
    return len(df) / span if span else 0.0


def per_second(df: pd.DataFrame) -> pd.DataFrame:
    attack = is_attack(df["label"])
    seconds = df["recorded_at"].dt.floor("s")
    counts = pd.DataFrame({"second": seconds, "attacks": attack.astype(int)})
    grouped = counts.groupby("second")["attacks"].agg(["count", "sum"])
    return pd.DataFrame(
        {"benign": grouped["count"] - grouped["sum"], "attacks": grouped["sum"]}
    )


def sessions() -> pd.DataFrame:
    df = pd.read_sql_query(
        "SELECT s.id, s.source, s.started_at, s.ended_at, "
        "COUNT(f.id) AS flows, "
        f"COALESCE(SUM(f.label != '{BENIGN}'), 0) AS attacks "
        "FROM sessions s LEFT JOIN classified_flow f ON f.session_id = s.id "
        "GROUP BY s.id ORDER BY s.id DESC",
        connect(),
    )
    fmt = "%Y-%m-%d %H:%M:%S"
    df["started_at"] = pd.to_datetime(df["started_at"], unit="s").dt.strftime(fmt)
    ended = pd.to_datetime(df["ended_at"], unit="s").dt.strftime(fmt)
    df["ended_at"] = ended.fillna("running")
    return df


def highlight_attacks(row: pd.Series) -> list[str]:
    attacked = is_attack(row["label"])
    style = "background-color: rgba(220,53,69,0.18)" if attacked else ""
    return [style] * len(row)


@st.fragment(run_every="1s")
def view() -> None:
    df = recent_flows()
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
    st.dataframe(sessions(), use_container_width=True, hide_index=True)


st.set_page_config(page_title="flow-ids", layout="wide")
st.title("flow-ids")
view()
