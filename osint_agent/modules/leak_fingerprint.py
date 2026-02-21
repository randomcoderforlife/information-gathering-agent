from __future__ import annotations

import hashlib
import re
import pandas as pd


SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def to_sha256(value: str) -> str:
    if SHA256_RE.match(value):
        return value.lower()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_values(df: pd.DataFrame, column: str = "value") -> pd.DataFrame:
    if df.empty or column not in df.columns:
        return pd.DataFrame(columns=["value", "sha256"])
    local_df = df.copy()
    local_df[column] = local_df[column].fillna("").astype(str)
    local_df = local_df[local_df[column].str.len() > 0]
    local_df["sha256"] = local_df[column].apply(to_sha256)
    return local_df[[column, "sha256"]].drop_duplicates().reset_index(drop=True)


def compare_fingerprints(
    asset_df: pd.DataFrame,
    observed_df: pd.DataFrame,
    value_column: str = "value",
) -> pd.DataFrame:
    normalized_assets = normalize_values(asset_df, value_column)
    normalized_observed = normalize_values(observed_df, value_column)

    if normalized_assets.empty or normalized_observed.empty:
        return pd.DataFrame(columns=["asset_value", "observed_value", "sha256"])

    merged = normalized_assets.merge(
        normalized_observed,
        on="sha256",
        how="inner",
        suffixes=("_asset", "_observed"),
    )
    if merged.empty:
        return pd.DataFrame(columns=["asset_value", "observed_value", "sha256"])

    return merged.rename(
        columns={f"{value_column}_asset": "asset_value", f"{value_column}_observed": "observed_value"}
    )[["asset_value", "observed_value", "sha256"]]

