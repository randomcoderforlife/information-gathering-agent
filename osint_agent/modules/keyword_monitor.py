from __future__ import annotations

from typing import Iterable
import pandas as pd


def monitor_keywords(
    feed_df: pd.DataFrame,
    keywords: Iterable[str],
    text_column: str = "content",
) -> pd.DataFrame:
    if feed_df.empty or text_column not in feed_df.columns:
        return pd.DataFrame(columns=["timestamp", "source", "content", "keyword"])

    cleaned_keywords = [k.strip().lower() for k in keywords if k and k.strip()]
    if not cleaned_keywords:
        return pd.DataFrame(columns=["timestamp", "source", "content", "keyword"])

    local_df = feed_df.copy()
    local_df[text_column] = local_df[text_column].fillna("").astype(str)
    matches: list[dict[str, str]] = []

    for _, row in local_df.iterrows():
        text = row[text_column].lower()
        for keyword in cleaned_keywords:
            if keyword in text:
                matches.append(
                    {
                        "timestamp": str(row.get("timestamp", "")),
                        "source": str(row.get("source", "")),
                        "content": str(row.get(text_column, "")),
                        "keyword": keyword,
                    }
                )

    return pd.DataFrame(matches, columns=["timestamp", "source", "content", "keyword"])

