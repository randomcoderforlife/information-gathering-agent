from __future__ import annotations

import networkx as nx
import pandas as pd
import plotly.graph_objects as go


def build_knowledge_graph(
    events_df: pd.DataFrame,
    mitre_hits_df: pd.DataFrame,
    wallet_clusters_df: pd.DataFrame,
) -> nx.Graph:
    g = nx.Graph()

    if not events_df.empty:
        for _, row in events_df.iterrows():
            actor = str(row.get("actor", "")).strip()
            indicator = str(row.get("indicator_value", "")).strip()
            wallet = str(row.get("wallet", "")).strip()
            event_id = str(row.get("event_id", "")).strip()

            if event_id:
                g.add_node(event_id, type="event")
            if actor:
                g.add_node(actor, type="actor")
            if indicator:
                g.add_node(indicator, type="indicator")
            if wallet:
                g.add_node(wallet, type="wallet")

            if event_id and actor:
                g.add_edge(event_id, actor, relation="attributed_to")
            if event_id and indicator:
                g.add_edge(event_id, indicator, relation="contains_indicator")
            if event_id and wallet:
                g.add_edge(event_id, wallet, relation="references_wallet")

    if not mitre_hits_df.empty:
        for _, row in mitre_hits_df.iterrows():
            actor = str(row.get("actor", "")).strip()
            technique_id = str(row.get("technique_id", "")).strip()
            if technique_id:
                g.add_node(technique_id, type="mitre_technique")
            if actor and technique_id:
                g.add_edge(actor, technique_id, relation="uses_technique")

    if not wallet_clusters_df.empty:
        cluster_to_wallets = wallet_clusters_df.groupby("cluster_id")["wallet"].apply(list).to_dict()
        for cluster_id, wallets in cluster_to_wallets.items():
            cluster_node = f"cluster:{cluster_id}"
            g.add_node(cluster_node, type="wallet_cluster")
            for wallet in wallets:
                wallet = str(wallet).strip()
                if wallet:
                    g.add_node(wallet, type="wallet")
                    g.add_edge(cluster_node, wallet, relation="contains_wallet")

    return g


def graph_to_plotly(g: nx.Graph) -> go.Figure:
    fig = go.Figure()
    if g.number_of_nodes() == 0:
        fig.update_layout(title="Knowledge Graph (no data)", template="plotly_white")
        return fig

    pos = nx.spring_layout(g, seed=42, k=0.5)

    edge_x: list[float] = []
    edge_y: list[float] = []
    for edge in g.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(width=0.8, color="#8c8c8c"),
        hoverinfo="none",
    )

    node_x: list[float] = []
    node_y: list[float] = []
    node_text: list[str] = []
    node_color: list[str] = []

    palette = {
        "event": "#1f77b4",
        "actor": "#d62728",
        "indicator": "#ff7f0e",
        "wallet": "#2ca02c",
        "wallet_cluster": "#9467bd",
        "mitre_technique": "#17becf",
    }

    for node, data in g.nodes(data=True):
        x, y = pos[node]
        node_type = data.get("type", "unknown")
        node_x.append(x)
        node_y.append(y)
        node_text.append(f"{node} ({node_type})")
        node_color.append(palette.get(node_type, "#7f7f7f"))

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers",
        hoverinfo="text",
        marker=dict(size=10, color=node_color, line=dict(width=0.5, color="#333")),
        text=node_text,
    )

    fig.add_trace(edge_trace)
    fig.add_trace(node_trace)
    fig.update_layout(
        title="Knowledge Graph",
        showlegend=False,
        margin=dict(l=10, r=10, t=40, b=10),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        template="plotly_white",
    )
    return fig

