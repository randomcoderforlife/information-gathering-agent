from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
from html import unescape
import re
from typing import Iterable
from urllib.parse import parse_qs, quote_plus, unquote, urldefrag, urlparse

from bs4 import BeautifulSoup
import pandas as pd
import requests

from osint_agent.modules.live_feeds import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, fetch_web_pages


STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "has",
    "he",
    "in",
    "is",
    "it",
    "its",
    "of",
    "on",
    "or",
    "that",
    "the",
    "to",
    "was",
    "were",
    "will",
    "with",
    "what",
    "who",
    "where",
    "when",
    "how",
    "why",
    "can",
    "do",
    "does",
    "i",
    "you",
    "we",
    "they",
    "this",
    "those",
    "these",
    "about",
    "into",
    "over",
    "under",
    "more",
    "most",
    "latest",
    "recent",
    "today",
}


@dataclass
class ResearchReport:
    prompt: str
    queries: list[str]
    summary: str
    findings: list[str]
    sources_df: pd.DataFrame
    pages_df: pd.DataFrame
    errors: list[str]


class AutonomousResearchAgent:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT):
        self.timeout = timeout
        self.user_agent = user_agent

    def run(
        self,
        prompt: str,
        max_queries: int = 4,
        max_results_per_query: int = 5,
        max_total_results: int = 20,
        max_pages_to_scrape: int = 10,
        include_duckduckgo: bool = True,
        include_wikipedia: bool = True,
        scrape_pages: bool = True,
    ) -> ResearchReport:
        query_text = str(prompt or "").strip()
        if not query_text:
            return ResearchReport(
                prompt="",
                queries=[],
                summary="No prompt provided.",
                findings=[],
                sources_df=self._empty_sources_df(),
                pages_df=self._empty_pages_df(),
                errors=["Prompt is empty."],
            )

        queries = self.generate_queries(query_text, max_queries=max_queries)
        errors: list[str] = []
        source_rows: list[dict[str, str]] = []

        for query in queries:
            if include_duckduckgo:
                ddg_rows, ddg_errors = self.search_duckduckgo(query, max_results=max_results_per_query)
                source_rows.extend(ddg_rows)
                errors.extend(ddg_errors)
            if include_wikipedia:
                wiki_rows, wiki_errors = self.search_wikipedia(query, max_results=max_results_per_query)
                source_rows.extend(wiki_rows)
                errors.extend(wiki_errors)

        sources_df = self._dedupe_sources(source_rows, max_total=max_total_results)
        pages_df = self._empty_pages_df()
        if scrape_pages and not sources_df.empty:
            scrape_df, scrape_errors = fetch_web_pages(
                urls=sources_df["url"].tolist(),
                follow_same_domain_links=False,
                same_domain_only=True,
                respect_robots_txt=True,
                max_pages=max_pages_to_scrape,
                max_links_per_page=1,
                max_chars=5000,
                timeout=self.timeout,
                user_agent=self.user_agent,
            )
            pages_df = scrape_df
            errors.extend(scrape_errors)

        summary, findings = self.summarize_research(query_text, sources_df, pages_df)
        return ResearchReport(
            prompt=query_text,
            queries=queries,
            summary=summary,
            findings=findings,
            sources_df=sources_df,
            pages_df=pages_df,
            errors=errors,
        )

    def generate_queries(self, prompt: str, max_queries: int = 4) -> list[str]:
        prompt = str(prompt).strip()
        if not prompt:
            return []

        tokens = self._tokens(prompt)
        counts = Counter(tokens)
        top_terms = [term for term, _ in counts.most_common(10)]

        queries = [prompt]
        if top_terms:
            chunk_size = 3
            for i in range(0, len(top_terms), chunk_size):
                chunk = top_terms[i : i + chunk_size]
                if not chunk:
                    continue
                queries.append(" ".join(chunk))
                if len(queries) >= max_queries:
                    break

        # Keep order, remove duplicates.
        deduped: list[str] = []
        for q in queries:
            if q not in deduped:
                deduped.append(q)
        return deduped[: max(1, int(max_queries))]

    def search_duckduckgo(self, query: str, max_results: int = 5) -> tuple[list[dict[str, str]], list[str]]:
        url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
        headers = {"User-Agent": self.user_agent}
        errors: list[str] = []

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
        except Exception as exc:
            return ([], [f"DuckDuckGo search failed for '{query}': {exc}"])

        soup = BeautifulSoup(resp.text, "html.parser")
        rows: list[dict[str, str]] = []
        for result in soup.select("div.result"):
            link_tag = result.select_one("a.result__a")
            if not link_tag:
                continue
            title = link_tag.get_text(" ", strip=True)
            href = str(link_tag.get("href", "")).strip()
            final_url = self._resolve_duckduckgo_redirect(href)
            if not self._is_http_url(final_url):
                continue
            snippet_tag = result.select_one(".result__snippet")
            snippet = snippet_tag.get_text(" ", strip=True) if snippet_tag else ""

            rows.append(
                {
                    "query": query,
                    "source_engine": "duckduckgo",
                    "title": title,
                    "url": final_url,
                    "snippet": snippet,
                }
            )
            if len(rows) >= max(1, int(max_results)):
                break

        if not rows:
            errors.append(f"No DuckDuckGo results parsed for '{query}'.")
        return (rows, errors)

    def search_wikipedia(self, query: str, max_results: int = 5) -> tuple[list[dict[str, str]], list[str]]:
        url = "https://en.wikipedia.org/w/api.php"
        params = {
            "action": "query",
            "list": "search",
            "srsearch": query,
            "srlimit": max(1, int(max_results)),
            "format": "json",
            "utf8": "1",
        }
        headers = {"User-Agent": self.user_agent}

        try:
            resp = requests.get(url, params=params, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            payload = resp.json()
        except Exception as exc:
            return ([], [f"Wikipedia search failed for '{query}': {exc}"])

        rows: list[dict[str, str]] = []
        search_items = payload.get("query", {}).get("search", [])
        for item in search_items:
            title = str(item.get("title", "")).strip()
            page_id = str(item.get("pageid", "")).strip()
            snippet = self._strip_html(str(item.get("snippet", "")))
            if not page_id:
                continue
            page_url = f"https://en.wikipedia.org/?curid={page_id}"
            rows.append(
                {
                    "query": query,
                    "source_engine": "wikipedia",
                    "title": title,
                    "url": page_url,
                    "snippet": snippet,
                }
            )

        return (rows, [])

    def summarize_research(
        self,
        prompt: str,
        sources_df: pd.DataFrame,
        pages_df: pd.DataFrame,
        max_findings: int = 6,
    ) -> tuple[str, list[str]]:
        if sources_df.empty and pages_df.empty:
            return ("No research results were collected.", [])

        keywords = set(self._tokens(prompt))
        sentences: list[str] = []

        if not pages_df.empty:
            for text in pages_df["summary"].fillna("").astype(str).tolist():
                sentences.extend(self._split_sentences(text))

        if not sources_df.empty:
            source_text = (
                sources_df["title"].fillna("").astype(str) + ". " + sources_df["snippet"].fillna("").astype(str)
            )
            for text in source_text.tolist():
                sentences.extend(self._split_sentences(text))

        scored: list[tuple[float, str]] = []
        for sentence in sentences:
            cleaned = sentence.strip()
            if len(cleaned) < 25:
                continue
            words = set(self._tokens(cleaned))
            overlap = len(words.intersection(keywords))
            if overlap == 0:
                continue
            score = overlap * 3 + min(len(cleaned) / 180, 1.5)
            scored.append((score, cleaned))

        scored.sort(key=lambda x: x[0], reverse=True)
        findings: list[str] = []
        seen: set[str] = set()
        for _, text in scored:
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            findings.append(text)
            if len(findings) >= max(1, int(max_findings)):
                break

        if not findings:
            findings = self._fallback_findings(sources_df)

        if findings:
            summary = " ".join(findings[:3])
        else:
            summary = "Research completed but no high-confidence findings were extracted."
        return (summary, findings)

    def _dedupe_sources(self, rows: Iterable[dict[str, str]], max_total: int) -> pd.DataFrame:
        if not rows:
            return self._empty_sources_df()
        df = pd.DataFrame(rows, columns=["query", "source_engine", "title", "url", "snippet"])
        df["url"] = df["url"].fillna("").astype(str).apply(lambda u: urldefrag(u)[0].strip())
        df = df[df["url"].str.len() > 0]
        if df.empty:
            return self._empty_sources_df()
        df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
        return df.head(max(1, int(max_total))).reset_index(drop=True)

    def _resolve_duckduckgo_redirect(self, href: str) -> str:
        raw = str(href or "").strip()
        if not raw:
            return ""
        if raw.startswith("//"):
            raw = "https:" + raw
        parsed = urlparse(raw)
        if "duckduckgo.com" in parsed.netloc and "uddg" in parsed.query:
            q = parse_qs(parsed.query)
            uddg = q.get("uddg", [])
            if uddg:
                return unquote(uddg[0])
        return raw

    def _is_http_url(self, url: str) -> bool:
        parsed = urlparse(str(url or "").strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def _tokens(self, text: str) -> list[str]:
        words = re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]*", str(text or "").lower())
        return [w for w in words if len(w) > 2 and w not in STOPWORDS]

    def _split_sentences(self, text: str) -> list[str]:
        chunks = re.split(r"(?<=[.!?])\s+", str(text or "").strip())
        return [c.strip() for c in chunks if c and c.strip()]

    def _strip_html(self, text: str) -> str:
        return re.sub(r"\s+", " ", BeautifulSoup(unescape(str(text or "")), "html.parser").get_text(" ")).strip()

    def _fallback_findings(self, sources_df: pd.DataFrame, max_findings: int = 6) -> list[str]:
        if sources_df.empty:
            return []
        findings: list[str] = []
        for _, row in sources_df.head(max_findings).iterrows():
            title = str(row.get("title", "")).strip()
            snippet = str(row.get("snippet", "")).strip()
            url = str(row.get("url", "")).strip()
            text = " ".join([x for x in [title, snippet] if x]).strip()
            if url:
                text = f"{text} (source: {url})"
            if text:
                findings.append(text)
        return findings

    def _empty_sources_df(self) -> pd.DataFrame:
        return pd.DataFrame(columns=["query", "source_engine", "title", "url", "snippet"])

    def _empty_pages_df(self) -> pd.DataFrame:
        return pd.DataFrame(columns=["timestamp", "source", "title", "summary", "link", "entry_id"])

