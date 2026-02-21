from __future__ import annotations

from pathlib import Path
import json
import pandas as pd


DEFAULT_MAP_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_keywords.json"


class MitreMapper:
    def __init__(self, mapping_path: str | None = None):
        target = Path(mapping_path) if mapping_path else DEFAULT_MAP_PATH
        with target.open("r", encoding="utf-8") as f:
            self.mapping = json.load(f)

    def map_events(
        self,
        events_df: pd.DataFrame,
        text_column: str = "description",
    ) -> pd.DataFrame:
        if events_df.empty or text_column not in events_df.columns:
            return pd.DataFrame(
                columns=[
                    "event_id",
                    "actor",
                    "keyword",
                    "tactic",
                    "technique_id",
                    "technique_name",
                ]
            )

        hits: list[dict[str, str]] = []
        local_df = events_df.copy()
        local_df[text_column] = local_df[text_column].fillna("").astype(str)

        for _, row in local_df.iterrows():
            text = row[text_column].lower()
            for rule in self.mapping:
                keyword = str(rule.get("keyword", "")).lower()
                if keyword and keyword in text:
                    hits.append(
                        {
                            "event_id": str(row.get("event_id", "")),
                            "actor": str(row.get("actor", "")),
                            "keyword": keyword,
                            "tactic": str(rule.get("tactic", "")),
                            "technique_id": str(rule.get("technique_id", "")),
                            "technique_name": str(rule.get("technique_name", "")),
                        }
                    )

        return pd.DataFrame(
            hits,
            columns=[
                "event_id",
                "actor",
                "keyword",
                "tactic",
                "technique_id",
                "technique_name",
            ],
        )

