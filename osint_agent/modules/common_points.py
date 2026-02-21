from __future__ import annotations

from collections import defaultdict
import re
from urllib.parse import urlparse
from typing import Iterable

import pandas as pd


STOPWORDS = {
    "about",
    "after",
    "also",
    "and",
    "are",
    "been",
    "between",
    "but",
    "can",
    "could",
    "data",
    "does",
    "each",
    "for",
    "from",
    "have",
    "into",
    "just",
    "more",
    "most",
    "news",
    "not",
    "our",
    "over",
    "than",
    "that",
    "the",
    "their",
    "there",
    "these",
    "they",
    "this",
    "those",
    "using",
    "what",
    "when",
    "which",
    "while",
    "with",
    "your",
}

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{3,}")


def _clean_url(url: str) -> str:
    return str(url or "").strip().rstrip(".,);]}>")


def _clean_value(value: str) -> str:
    return str(value or "").strip().strip(".,;:()[]{}<>\"'")


def _tokenize_keywords(text: str) -> set[str]:
    tokens = set()
    for token in WORD_RE.findall(str(text or "").lower()):
        if token in STOPWORDS:
            continue
        if token.isdigit():
            continue
        tokens.add(token)
    return tokens


def _extract_points_from_text(text: str) -> dict[str, set[str]]:
    points: dict[str, set[str]] = defaultdict(set)
    if not text:
        return points

    raw = str(text)

    for match in CVE_RE.findall(raw):
        points["cve"].add(match.upper())

    for match in MITRE_RE.findall(raw):
        points["mitre_technique"].add(match.upper())

    for match in IPV4_RE.findall(raw):
        points["ip"].add(match)

    for match in URL_RE.findall(raw):
        cleaned_url = _clean_url(match)
        points["url"].add(cleaned_url)
        host = urlparse(cleaned_url).netloc.lower()
        if host:
            points["domain"].add(host)

    for match in DOMAIN_RE.findall(raw):
        domain = _clean_value(match).lower()
        if domain and "." in domain:
            points["domain"].add(domain)

    for token in _tokenize_keywords(raw):
        points["keyword"].add(token)

    return points


def extract_common_points(
    texts: Iterable[str],
    labels: Iterable[str] | None = None,
    min_support: int = 2,
    top_n: int = 40,
) -> pd.DataFrame:
    docs = [str(t or "") for t in texts]
    if not docs:
        return pd.DataFrame(columns=["point_type", "value", "support", "evidence"])

    label_list = list(labels) if labels is not None else []
    if len(label_list) != len(docs):
        label_list = [f"doc_{i+1}" for i in range(len(docs))]

    support: dict[tuple[str, str], int] = defaultdict(int)
    evidence: dict[tuple[str, str], list[str]] = defaultdict(list)

    for idx, text in enumerate(docs):
        label = label_list[idx]
        points = _extract_points_from_text(text)
        seen_in_doc: set[tuple[str, str]] = set()

        for point_type, values in points.items():
            for value in values:
                key = (point_type, value)
                if key in seen_in_doc:
                    continue
                seen_in_doc.add(key)
                support[key] += 1
                if len(evidence[key]) < 3:
                    evidence[key].append(label)

    rows: list[dict[str, str | int]] = []
    threshold = max(1, int(min_support))
    for (point_type, value), count in support.items():
        if count < threshold:
            continue
        rows.append(
            {
                "point_type": point_type,
                "value": value,
                "support": int(count),
                "evidence": ", ".join(evidence.get((point_type, value), [])),
            }
        )

    if not rows:
        return pd.DataFrame(columns=["point_type", "value", "support", "evidence"])

    df = pd.DataFrame(rows, columns=["point_type", "value", "support", "evidence"])
    order = {"cve": 0, "mitre_technique": 1, "domain": 2, "ip": 3, "url": 4, "keyword": 5}
    df["type_order"] = df["point_type"].map(order).fillna(99)
    df = df.sort_values(["support", "type_order", "value"], ascending=[False, True, True]).drop(columns=["type_order"])
    return df.head(max(1, int(top_n))).reset_index(drop=True)


def build_common_points_from_frames(
    events_df: pd.DataFrame | None = None,
    keyword_feed_df: pd.DataFrame | None = None,
    sources_df: pd.DataFrame | None = None,
    pages_df: pd.DataFrame | None = None,
    min_support: int = 2,
    top_n: int = 40,
) -> pd.DataFrame:
    texts: list[str] = []
    labels: list[str] = []

    if events_df is not None and not events_df.empty:
        work = events_df.fillna("").astype(str)
        for idx, row in work.iterrows():
            text = " ".join(
                [
                    row.get("event_id", ""),
                    row.get("source", ""),
                    row.get("description", ""),
                    row.get("indicator_value", ""),
                ]
            ).strip()
            if text:
                texts.append(text)
                labels.append(row.get("source", f"event_{idx}"))

    if keyword_feed_df is not None and not keyword_feed_df.empty:
        work = keyword_feed_df.fillna("").astype(str)
        for idx, row in work.iterrows():
            text = " ".join([row.get("source", ""), row.get("content", "")]).strip()
            if text:
                texts.append(text)
                labels.append(row.get("source", f"feed_{idx}"))

    if sources_df is not None and not sources_df.empty:
        work = sources_df.fillna("").astype(str)
        for idx, row in work.iterrows():
            text = " ".join([row.get("title", ""), row.get("snippet", ""), row.get("url", "")]).strip()
            if text:
                texts.append(text)
                labels.append(row.get("source_engine", f"source_{idx}"))

    if pages_df is not None and not pages_df.empty:
        work = pages_df.fillna("").astype(str)
        for idx, row in work.iterrows():
            text = " ".join([row.get("title", ""), row.get("summary", ""), row.get("link", "")]).strip()
            if text:
                texts.append(text)
                labels.append(row.get("source", f"page_{idx}"))

    return extract_common_points(texts=texts, labels=labels, min_support=min_support, top_n=top_n)

