from collections.abc import Mapping
from typing import TypeAlias

FlowValue: TypeAlias = str | int | float
FlowData: TypeAlias = Mapping[str, FlowValue]

FEATURE_ALIASES = (
    ("fwd_seg_size_avg", "fwd_pkt_len_mean"),
    ("bwd_seg_size_avg", "bwd_pkt_len_mean"),
    ("subflow_fwd_pkts", "tot_fwd_pkts"),
    ("subflow_bwd_pkts", "tot_bwd_pkts"),
    ("subflow_fwd_byts", "totlen_fwd_pkts"),
    ("subflow_bwd_byts", "totlen_bwd_pkts"),
)
