from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import html
import os
import re
from urllib import robotparser
from urllib.parse import urldefrag, urljoin, urlparse
from typing import Iterable

from bs4 import BeautifulSoup
import feedparser
import pandas as pd
import requests


DEFAULT_TIMEOUT = 25
DEFAULT_USER_AGENT = "OSINTResearchAgent/1.0 (+legal-public-intel-only)"

DEFAULT_RSS_URLS = [
    "https://www.cisa.gov/news.xml",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.cisa.gov/uscert/ncas/all.xml",
]

DEFAULT_CISA_KEV_JSON_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]


@dataclass
class LiveFeedFetchResult:
    events_df: pd.DataFrame
    keyword_feed_df: pd.DataFrame
    raw_items_df: pd.DataFrame
    errors: list[str]


def _empty_events_df() -> pd.DataFrame:
    return pd.DataFrame(
        columns=[
            "event_id",
            "timestamp",
            "source",
            "actor",
            "description",
            "indicator_type",
            "indicator_value",
            "wallet",
        ]
    )


def _empty_keyword_df() -> pd.DataFrame:
    return pd.DataFrame(columns=["timestamp", "source", "content"])


def _empty_raw_df() -> pd.DataFrame:
    return pd.DataFrame(columns=["timestamp", "source", "title", "summary", "link", "entry_id"])


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha12(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _strip_html(text: str) -> str:
    text = html.unescape(text or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _parse_datetime(value: str | datetime | None) -> datetime:
    if value is None:
        return _now_utc()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    raw = str(value).strip()
    if not raw:
        return _now_utc()

    try:
        return parsedate_to_datetime(raw).astimezone(timezone.utc)
    except Exception:
        pass

    try:
        dt = pd.to_datetime(raw, utc=True)
        if isinstance(dt, pd.Timestamp):
            return dt.to_pydatetime().astimezone(timezone.utc)
    except Exception:
        pass

    return _now_utc()


def _to_iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _request_json(url: str, headers: dict[str, str] | None = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    hdrs = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        hdrs.update(headers)
    resp = requests.get(url, headers=hdrs, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _request_text(url: str, headers: dict[str, str] | None = None, timeout: int = DEFAULT_TIMEOUT) -> str:
    hdrs = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        hdrs.update(headers)
    resp = requests.get(url, headers=hdrs, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def fetch_rss_feed(
    url: str,
    source_label: str | None = None,
    lookback_days: int = 7,
    max_items: int = 200,
    timeout: int = DEFAULT_TIMEOUT,
) -> pd.DataFrame:
    text = _request_text(url, timeout=timeout)
    parsed = feedparser.parse(text)
    cutoff = _now_utc() - timedelta(days=max(1, lookback_days))
    rows: list[dict[str, str]] = []

    for entry in parsed.entries:
        published_raw = getattr(entry, "published", None) or getattr(entry, "updated", None)
        published_dt = _parse_datetime(published_raw)
        if published_dt < cutoff:
            continue

        title = _strip_html(getattr(entry, "title", ""))
        summary = _strip_html(getattr(entry, "summary", "")) or _strip_html(getattr(entry, "description", ""))
        link = str(getattr(entry, "link", "")).strip()
        entry_id = str(getattr(entry, "id", "")).strip() or _sha12(f"{url}|{title}|{published_dt.isoformat()}")
        source = source_label or parsed.feed.get("title") or url

        rows.append(
            {
                "timestamp": _to_iso_z(published_dt),
                "source": str(source),
                "title": title,
                "summary": summary,
                "link": link,
                "entry_id": entry_id,
            }
        )
        if len(rows) >= max_items:
            break

    if not rows:
        return _empty_raw_df()
    return pd.DataFrame(rows, columns=["timestamp", "source", "title", "summary", "link", "entry_id"])


def fetch_rss_batch(
    urls: Iterable[str],
    lookback_days: int = 7,
    max_items_per_feed: int = 100,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[pd.DataFrame, list[str]]:
    frames: list[pd.DataFrame] = []
    errors: list[str] = []

    for raw_url in urls:
        url = str(raw_url).strip()
        if not url:
            continue
        try:
            frame = fetch_rss_feed(
                url=url,
                source_label=url,
                lookback_days=lookback_days,
                max_items=max_items_per_feed,
                timeout=timeout,
            )
            if not frame.empty:
                frames.append(frame)
        except Exception as exc:
            errors.append(f"RSS fetch failed for {url}: {exc}")

    if not frames:
        return (_empty_raw_df(), errors)
    out = pd.concat(frames, ignore_index=True).drop_duplicates(subset=["entry_id", "link"])
    return (out, errors)


def fetch_nvd_cves(
    lookback_days: int = 3,
    max_results: int = 200,
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[pd.DataFrame, list[str]]:
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    end_dt = _now_utc()
    start_dt = end_dt - timedelta(days=max(1, lookback_days))

    params = {
        "resultsPerPage": max(1, min(2000, int(max_results))),
        "startIndex": 0,
        "pubStartDate": _to_iso_z(start_dt),
        "pubEndDate": _to_iso_z(end_dt),
    }
    headers: dict[str, str] = {}
    key = (api_key or os.getenv("NVD_API_KEY", "")).strip()
    if key:
        headers["apiKey"] = key

    errors: list[str] = []
    payload: dict
    try:
        hdrs = {"User-Agent": DEFAULT_USER_AGENT}
        hdrs.update(headers)
        resp = requests.get(base_url, params=params, headers=hdrs, timeout=timeout)
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        # Retry without date filters if upstream rejects a time-format variant.
        try:
            payload = _request_json(base_url, headers=headers, timeout=timeout if timeout else DEFAULT_TIMEOUT)
        except Exception as exc:
            errors.append(f"NVD fetch failed: {exc}")
            return (_empty_events_df(), errors)

    items = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    rows: list[dict[str, str]] = []
    for item in items:
        cve = item.get("cve", {}) if isinstance(item, dict) else {}
        cve_id = str(cve.get("id", "")).strip()
        if not cve_id:
            continue
        published_dt = _parse_datetime(cve.get("published"))
        if published_dt < start_dt or published_dt > end_dt + timedelta(minutes=5):
            continue

        published = _to_iso_z(published_dt)
        descriptions = cve.get("descriptions", []) or []
        desc = ""
        for d in descriptions:
            if str(d.get("lang", "")).lower() == "en":
                desc = str(d.get("value", ""))
                break
        if not desc and descriptions:
            desc = str(descriptions[0].get("value", ""))

        rows.append(
            {
                "event_id": f"NVD-{cve_id}",
                "timestamp": published,
                "source": "nvd_api",
                "actor": "unknown",
                "description": desc,
                "indicator_type": "cve",
                "indicator_value": cve_id,
                "wallet": "",
            }
        )

    if not rows and not errors:
        # If date-filtered fetch returned empty due formatting mismatch, fallback once.
        try:
            payload = _request_json(base_url, headers=headers, timeout=timeout if timeout else DEFAULT_TIMEOUT)
            items = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
            for item in items:
                cve = item.get("cve", {}) if isinstance(item, dict) else {}
                cve_id = str(cve.get("id", "")).strip()
                if not cve_id:
                    continue
                published_dt = _parse_datetime(cve.get("published"))
                if published_dt < start_dt:
                    continue

                descriptions = cve.get("descriptions", []) or []
                desc = ""
                for d in descriptions:
                    if str(d.get("lang", "")).lower() == "en":
                        desc = str(d.get("value", ""))
                        break
                if not desc and descriptions:
                    desc = str(descriptions[0].get("value", ""))

                rows.append(
                    {
                        "event_id": f"NVD-{cve_id}",
                        "timestamp": _to_iso_z(published_dt),
                        "source": "nvd_api",
                        "actor": "unknown",
                        "description": desc,
                        "indicator_type": "cve",
                        "indicator_value": cve_id,
                        "wallet": "",
                    }
                )
        except Exception as exc:
            errors.append(f"NVD fallback fetch failed: {exc}")
            return (_empty_events_df(), errors)

    if not rows:
        return (_empty_events_df(), errors)
    out = pd.DataFrame(
        rows,
        columns=[
            "event_id",
            "timestamp",
            "source",
            "actor",
            "description",
            "indicator_type",
            "indicator_value",
            "wallet",
        ],
    ).drop_duplicates(subset=["event_id"])
    return (out, errors)


def fetch_cisa_kev(
    kev_urls: Iterable[str] | None = None,
    lookback_days: int = 14,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    urls = list(kev_urls) if kev_urls else DEFAULT_CISA_KEV_JSON_URLS
    errors: list[str] = []
    payload: dict | None = None

    for url in urls:
        try:
            payload = _request_json(url, timeout=timeout)
            if payload:
                break
        except Exception as exc:
            errors.append(f"CISA KEV fetch failed for {url}: {exc}")

    if not payload:
        return (_empty_events_df(), _empty_keyword_df(), errors)

    cutoff = _now_utc() - timedelta(days=max(1, lookback_days))
    vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    event_rows: list[dict[str, str]] = []
    keyword_rows: list[dict[str, str]] = []

    for v in vulns:
        cve_id = str(v.get("cveID", "")).strip()
        if not cve_id:
            continue

        added_dt = _parse_datetime(v.get("dateAdded"))
        if added_dt < cutoff:
            continue

        vendor = str(v.get("vendorProject", "")).strip()
        vuln_name = str(v.get("vulnerabilityName", "")).strip()
        short_desc = str(v.get("shortDescription", "")).strip()
        action = str(v.get("requiredAction", "")).strip()
        desc = " ".join([x for x in [vuln_name, short_desc, action] if x])
        ts = _to_iso_z(added_dt)

        event_rows.append(
            {
                "event_id": f"CISA-KEV-{cve_id}",
                "timestamp": ts,
                "source": "cisa_kev",
                "actor": vendor or "unknown",
                "description": desc,
                "indicator_type": "cve",
                "indicator_value": cve_id,
                "wallet": "",
            }
        )
        keyword_rows.append(
            {
                "timestamp": ts,
                "source": "cisa_kev",
                "content": f"{cve_id} {desc}",
            }
        )

    events_df = (
        pd.DataFrame(event_rows, columns=_empty_events_df().columns.tolist()).drop_duplicates(subset=["event_id"])
        if event_rows
        else _empty_events_df()
    )
    keyword_df = (
        pd.DataFrame(keyword_rows, columns=_empty_keyword_df().columns.tolist()).drop_duplicates()
        if keyword_rows
        else _empty_keyword_df()
    )
    return (events_df, keyword_df, errors)


def rss_items_to_events(raw_df: pd.DataFrame, source_prefix: str = "rss") -> pd.DataFrame:
    if raw_df.empty:
        return _empty_events_df()

    rows: list[dict[str, str]] = []
    for _, row in raw_df.iterrows():
        ts = _to_iso_z(_parse_datetime(row.get("timestamp")))
        title = str(row.get("title", "")).strip()
        summary = str(row.get("summary", "")).strip()
        source = str(row.get("source", "")).strip() or source_prefix
        link = str(row.get("link", "")).strip()
        entry_id = str(row.get("entry_id", "")).strip() or _sha12(f"{source}|{title}|{ts}")
        desc = " ".join([x for x in [title, summary, link] if x]).strip()

        rows.append(
            {
                "event_id": f"{source_prefix.upper()}-{entry_id}",
                "timestamp": ts,
                "source": source,
                "actor": "unknown",
                "description": desc,
                "indicator_type": "url" if link else "text",
                "indicator_value": link or title[:180],
                "wallet": "",
            }
        )

    return pd.DataFrame(rows, columns=_empty_events_df().columns.tolist()).drop_duplicates(subset=["event_id"])


def rss_items_to_keyword_feed(raw_df: pd.DataFrame) -> pd.DataFrame:
    if raw_df.empty:
        return _empty_keyword_df()
    out = raw_df.copy()
    out["content"] = (out["title"].fillna("").astype(str) + " " + out["summary"].fillna("").astype(str)).str.strip()
    return out[["timestamp", "source", "content"]].drop_duplicates().reset_index(drop=True)


def fetch_live_sources(
    rss_urls: Iterable[str] | None = None,
    include_default_rss: bool = True,
    lookback_days: int = 7,
    max_rss_items_per_feed: int = 100,
    fetch_nvd: bool = True,
    nvd_max_results: int = 200,
    nvd_api_key: str | None = None,
    fetch_cisa: bool = True,
) -> LiveFeedFetchResult:
    combined_events = _empty_events_df()
    combined_keyword = _empty_keyword_df()
    combined_raw = _empty_raw_df()
    errors: list[str] = []

    urls: list[str] = []
    if include_default_rss:
        urls.extend(DEFAULT_RSS_URLS)
    if rss_urls:
        urls.extend([str(x).strip() for x in rss_urls if str(x).strip()])
    urls = sorted(set(urls))

    if urls:
        raw_df, rss_errors = fetch_rss_batch(
            urls=urls,
            lookback_days=lookback_days,
            max_items_per_feed=max_rss_items_per_feed,
        )
        errors.extend(rss_errors)
        combined_raw = raw_df
        combined_events = pd.concat([combined_events, rss_items_to_events(raw_df)], ignore_index=True)
        combined_keyword = pd.concat([combined_keyword, rss_items_to_keyword_feed(raw_df)], ignore_index=True)

    if fetch_nvd:
        nvd_events, nvd_errors = fetch_nvd_cves(
            lookback_days=lookback_days,
            max_results=nvd_max_results,
            api_key=nvd_api_key,
        )
        errors.extend(nvd_errors)
        if not nvd_events.empty:
            nvd_keyword = pd.DataFrame(
                {
                    "timestamp": nvd_events["timestamp"],
                    "source": nvd_events["source"],
                    "content": nvd_events["indicator_value"] + " " + nvd_events["description"],
                }
            )
            combined_events = pd.concat([combined_events, nvd_events], ignore_index=True)
            combined_keyword = pd.concat([combined_keyword, nvd_keyword], ignore_index=True)

    if fetch_cisa:
        cisa_events, cisa_keyword, cisa_errors = fetch_cisa_kev(lookback_days=lookback_days)
        errors.extend(cisa_errors)
        combined_events = pd.concat([combined_events, cisa_events], ignore_index=True)
        combined_keyword = pd.concat([combined_keyword, cisa_keyword], ignore_index=True)

    if not combined_events.empty:
        combined_events = combined_events.drop_duplicates(subset=["event_id"]).reset_index(drop=True)
    if not combined_keyword.empty:
        combined_keyword = combined_keyword.drop_duplicates(subset=["timestamp", "source", "content"]).reset_index(
            drop=True
        )

    return LiveFeedFetchResult(
        events_df=combined_events if not combined_events.empty else _empty_events_df(),
        keyword_feed_df=combined_keyword if not combined_keyword.empty else _empty_keyword_df(),
        raw_items_df=combined_raw if not combined_raw.empty else _empty_raw_df(),
        errors=errors,
    )


def _is_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _normalize_seed_urls(urls: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    for raw in urls:
        url = str(raw).strip()
        if not url:
            continue
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        url = urldefrag(url)[0].strip()
        if _is_http_url(url):
            normalized.append(url)
    return sorted(set(normalized))


def _robots_can_fetch(
    url: str,
    user_agent: str,
    cache: dict[str, robotparser.RobotFileParser | None],
) -> bool:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    if base not in cache:
        rp = robotparser.RobotFileParser()
        rp.set_url(f"{base}/robots.txt")
        try:
            rp.read()
            cache[base] = rp
        except Exception:
            # If robots cannot be fetched, default to permissive and let the user decide.
            cache[base] = None
    if cache[base] is None:
        return True
    return cache[base].can_fetch(user_agent, url)


def _extract_html_content(raw_html: str, max_chars: int = 4000) -> tuple[str, str, list[str]]:
    soup = BeautifulSoup(raw_html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.extract()

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    text = " ".join(soup.stripped_strings)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars]

    links: list[str] = []
    for anchor in soup.find_all("a", href=True):
        href = str(anchor.get("href", "")).strip()
        if href:
            links.append(href)
    return (title, text, links)


def fetch_web_pages(
    urls: Iterable[str],
    follow_same_domain_links: bool = False,
    same_domain_only: bool = True,
    respect_robots_txt: bool = True,
    max_pages: int = 20,
    max_links_per_page: int = 8,
    max_chars: int = 4000,
    timeout: int = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> tuple[pd.DataFrame, list[str]]:
    seeds = _normalize_seed_urls(urls)
    if not seeds:
        return (_empty_raw_df(), ["No valid HTTP/HTTPS URLs provided."])

    queue: list[str] = list(seeds)
    visited: set[str] = set()
    errors: list[str] = []
    rows: list[dict[str, str]] = []
    robots_cache: dict[str, robotparser.RobotFileParser | None] = {}

    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})

    while queue and len(rows) < max(1, int(max_pages)):
        current = queue.pop(0)
        current = urldefrag(current)[0]
        if current in visited:
            continue
        visited.add(current)

        if not _is_http_url(current):
            continue
        if respect_robots_txt and not _robots_can_fetch(current, user_agent, robots_cache):
            errors.append(f"Blocked by robots.txt: {current}")
            continue

        try:
            response = session.get(current, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            final_url = urldefrag(str(response.url).strip())[0]
            content_type = str(response.headers.get("Content-Type", "")).lower()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                errors.append(f"Skipped non-HTML content: {final_url}")
                continue

            fetched_dt = _parse_datetime(response.headers.get("Date"))
            title, page_text, links = _extract_html_content(response.text, max_chars=max_chars)
            source = f"web:{urlparse(final_url).netloc}"
            entry_id = _sha12(f"{final_url}|{title}|{_to_iso_z(fetched_dt)}")
            rows.append(
                {
                    "timestamp": _to_iso_z(fetched_dt),
                    "source": source,
                    "title": title or final_url,
                    "summary": page_text,
                    "link": final_url,
                    "entry_id": entry_id,
                }
            )

            if follow_same_domain_links:
                added = 0
                base_host = urlparse(final_url).netloc
                for href in links:
                    if added >= max(1, int(max_links_per_page)):
                        break
                    absolute = urldefrag(urljoin(final_url, href))[0]
                    if not _is_http_url(absolute):
                        continue
                    if same_domain_only and urlparse(absolute).netloc != base_host:
                        continue
                    if absolute not in visited and absolute not in queue:
                        queue.append(absolute)
                        added += 1
        except Exception as exc:
            errors.append(f"Web scrape failed for {current}: {exc}")

    if not rows:
        return (_empty_raw_df(), errors)
    raw_df = pd.DataFrame(rows, columns=["timestamp", "source", "title", "summary", "link", "entry_id"])
    raw_df = raw_df.drop_duplicates(subset=["link"]).reset_index(drop=True)
    return (raw_df, errors)


def web_items_to_events(raw_df: pd.DataFrame, source_prefix: str = "web") -> pd.DataFrame:
    if raw_df.empty:
        return _empty_events_df()

    rows: list[dict[str, str]] = []
    for _, row in raw_df.iterrows():
        ts = _to_iso_z(_parse_datetime(row.get("timestamp")))
        title = str(row.get("title", "")).strip()
        summary = str(row.get("summary", "")).strip()
        source = str(row.get("source", "")).strip() or source_prefix
        link = str(row.get("link", "")).strip()
        entry_id = str(row.get("entry_id", "")).strip() or _sha12(f"{source}|{title}|{link}|{ts}")
        description = " ".join([x for x in [title, summary] if x]).strip()

        rows.append(
            {
                "event_id": f"{source_prefix.upper()}-{entry_id}",
                "timestamp": ts,
                "source": source,
                "actor": "unknown",
                "description": description,
                "indicator_type": "url",
                "indicator_value": link,
                "wallet": "",
            }
        )

    return pd.DataFrame(rows, columns=_empty_events_df().columns.tolist()).drop_duplicates(subset=["event_id"])


def web_items_to_keyword_feed(raw_df: pd.DataFrame) -> pd.DataFrame:
    if raw_df.empty:
        return _empty_keyword_df()
    out = raw_df.copy()
    out["content"] = (
        out["title"].fillna("").astype(str) + " " + out["summary"].fillna("").astype(str)
    ).str.strip()
    return out[["timestamp", "source", "content"]].drop_duplicates().reset_index(drop=True)


def fetch_web_scrape_sources(
    urls: Iterable[str],
    follow_same_domain_links: bool = False,
    same_domain_only: bool = True,
    respect_robots_txt: bool = True,
    max_pages: int = 20,
    max_links_per_page: int = 8,
    max_chars: int = 4000,
    timeout: int = DEFAULT_TIMEOUT,
) -> LiveFeedFetchResult:
    raw_df, errors = fetch_web_pages(
        urls=urls,
        follow_same_domain_links=follow_same_domain_links,
        same_domain_only=same_domain_only,
        respect_robots_txt=respect_robots_txt,
        max_pages=max_pages,
        max_links_per_page=max_links_per_page,
        max_chars=max_chars,
        timeout=timeout,
    )
    events_df = web_items_to_events(raw_df)
    keyword_df = web_items_to_keyword_feed(raw_df)
    return LiveFeedFetchResult(
        events_df=events_df if not events_df.empty else _empty_events_df(),
        keyword_feed_df=keyword_df if not keyword_df.empty else _empty_keyword_df(),
        raw_items_df=raw_df if not raw_df.empty else _empty_raw_df(),
        errors=errors,
    )
