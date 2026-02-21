from __future__ import annotations

from dataclasses import dataclass
import networkx as nx
import pandas as pd

from osint_agent.modules.keyword_monitor import monitor_keywords
from osint_agent.modules.leak_fingerprint import compare_fingerprints
from osint_agent.modules.mitre_mapper import MitreMapper
from osint_agent.modules.threat_actor import build_actor_profiles
from osint_agent.modules.wallet_cluster import cluster_wallets
from osint_agent.modules.graph_ops import build_knowledge_graph


@dataclass
class AnalysisResult:
    keyword_hits: pd.DataFrame
    mitre_hits: pd.DataFrame
    actor_profiles: pd.DataFrame
    wallet_clusters: pd.DataFrame
    leak_matches: pd.DataFrame
    knowledge_graph: nx.Graph


class OSINTResearchAgent:
    def __init__(self, mitre_mapping_path: str | None = None):
        self.mitre_mapper = MitreMapper(mitre_mapping_path)

    def analyze(
        self,
        events_df: pd.DataFrame,
        keyword_feed_df: pd.DataFrame,
        keywords: list[str],
        tx_df: pd.DataFrame,
        asset_hashes_df: pd.DataFrame,
        observed_hashes_df: pd.DataFrame,
    ) -> AnalysisResult:
        keyword_hits = monitor_keywords(keyword_feed_df, keywords, text_column="content")
        mitre_hits = self.mitre_mapper.map_events(events_df, text_column="description")
        actor_profiles = build_actor_profiles(events_df, mitre_hits)
        wallet_clusters = cluster_wallets(tx_df)
        leak_matches = compare_fingerprints(asset_hashes_df, observed_hashes_df, value_column="value")
        graph = build_knowledge_graph(events_df, mitre_hits, wallet_clusters)

        return AnalysisResult(
            keyword_hits=keyword_hits,
            mitre_hits=mitre_hits,
            actor_profiles=actor_profiles,
            wallet_clusters=wallet_clusters,
            leak_matches=leak_matches,
            knowledge_graph=graph,
        )

