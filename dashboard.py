import sqlite3

import pandas as pd
import streamlit as st

DB_PATH = "flows.db"


@st.cache_resource
def connect() -> sqlite3.Connection:
    return sqlite3.connect(
        f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False
    )


@st.fragment(run_every="1s")
def view() -> None:
    df = pd.read_sql_query(
        "SELECT recorded_at, src_ip, dst_ip, dst_port, label, confidence "
        "FROM flows ORDER BY recorded_at DESC LIMIT 2000",
        connect(),
    )
    df["recorded_at"] = pd.to_datetime(df["recorded_at"], unit="s")
    
    total, attacks = len(df), int((df["label"] != "BENIGN").sum())
    c1, c2 = st.columns(2)
    c1.metric("flows (recent)", total)
    c2.metric("non-benign", attacks)

    st.bar_chart(df["label"].value_counts())

    st.subheader("recent non-benign flows")
    st.dataframe(
        df[df["label"] != "BENIGN"], use_container_width=True, hide_index=True
    )


st.title("flow-ids")
view()
