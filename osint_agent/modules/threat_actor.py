from __future__ import annotations

import pandas as pd


def build_actor_profiles(events_df: pd.DataFrame, mitre_hits_df: pd.DataFrame) -> pd.DataFrame:
    if events_df.empty or "actor" not in events_df.columns:
        return pd.DataFrame(
            columns=[
                "actor",
                "event_count",
                "sources",
                "indicator_count",
                "wallet_count",
                "top_techniques",
            ]
        )

    work_df = events_df.copy()
    work_df["actor"] = work_df["actor"].fillna("unknown").astype(str)

    grouped = work_df.groupby("actor", dropna=False)

    rows: list[dict[str, str | int]] = []
    for actor, frame in grouped:
        techniques = []
        if not mitre_hits_df.empty and "actor" in mitre_hits_df.columns:
            tech_series = mitre_hits_df[mitre_hits_df["actor"] == actor]["technique_id"]
            techniques = sorted(set([str(t) for t in tech_series.dropna().tolist()]))

        sources = sorted(set(frame.get("source", pd.Series(dtype=str)).fillna("").astype(str)))
        indicators = frame.get("indicator_value", pd.Series(dtype=str)).fillna("").astype(str)
        wallets = frame.get("wallet", pd.Series(dtype=str)).fillna("").astype(str)
        wallets = wallets[wallets.str.len() > 0]

        rows.append(
            {
                "actor": actor,
                "event_count": int(len(frame)),
                "sources": ", ".join([s for s in sources if s]),
                "indicator_count": int(indicators[indicators.str.len() > 0].nunique()),
                "wallet_count": int(wallets.nunique()),
                "top_techniques": ", ".join(techniques[:6]),
            }
        )

    profile_df = pd.DataFrame(rows)
    if profile_df.empty:
        return profile_df
    return profile_df.sort_values("event_count", ascending=False).reset_index(drop=True)

