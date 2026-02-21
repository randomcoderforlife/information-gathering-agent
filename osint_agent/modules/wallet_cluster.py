from __future__ import annotations

import networkx as nx
import pandas as pd


def cluster_wallets(
    tx_df: pd.DataFrame,
    bad_wallets_df: pd.DataFrame | None = None,
) -> pd.DataFrame:
    if tx_df.empty:
        return pd.DataFrame(columns=["wallet", "cluster_id", "cluster_size", "risk_tag"])

    required = {"tx_hash", "from_wallet", "to_wallet"}
    if not required.issubset(set(tx_df.columns)):
        return pd.DataFrame(columns=["wallet", "cluster_id", "cluster_size", "risk_tag"])

    g = nx.Graph()
    work_df = tx_df.copy()
    work_df["from_wallet"] = work_df["from_wallet"].fillna("").astype(str)
    work_df["to_wallet"] = work_df["to_wallet"].fillna("").astype(str)
    work_df["tx_hash"] = work_df["tx_hash"].fillna("").astype(str)

    # Direct transfer relation
    for _, row in work_df.iterrows():
        src = row["from_wallet"].strip()
        dst = row["to_wallet"].strip()
        if src:
            g.add_node(src)
        if dst:
            g.add_node(dst)
        if src and dst:
            g.add_edge(src, dst, relation="transfer")

    # Co-spend heuristic: all senders in the same tx_hash are linked.
    for _, frame in work_df.groupby("tx_hash"):
        senders = sorted(set([w for w in frame["from_wallet"].tolist() if w]))
        if len(senders) > 1:
            for i in range(len(senders)):
                for j in range(i + 1, len(senders)):
                    g.add_edge(senders[i], senders[j], relation="co_spend")

    bad_wallets: set[str] = set()
    if bad_wallets_df is not None and not bad_wallets_df.empty and "wallet" in bad_wallets_df.columns:
        bad_wallets = set(bad_wallets_df["wallet"].fillna("").astype(str).tolist())

    rows: list[dict[str, str | int]] = []
    for idx, component in enumerate(nx.connected_components(g), start=1):
        members = sorted(component)
        cluster_size = len(members)
        for wallet in members:
            rows.append(
                {
                    "wallet": wallet,
                    "cluster_id": f"C{idx:04d}",
                    "cluster_size": cluster_size,
                    "risk_tag": "flagged" if wallet in bad_wallets else "unlabeled",
                }
            )

    result = pd.DataFrame(rows)
    if result.empty:
        return result
    return result.sort_values(["cluster_size", "cluster_id"], ascending=[False, True]).reset_index(drop=True)

