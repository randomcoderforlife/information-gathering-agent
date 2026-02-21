# OSINT Research Agent (Compliance-First)

A modular Python threat-intelligence application with a Streamlit GUI dashboard.

## Implemented capabilities

- OSINT event ingestion
- Live feed ingestion from legal/public sources (RSS, NVD CVE API, CISA KEV advisory feed)
- Optional public-web scraping for user-provided URLs
- Prompt-driven custom AI research agent with autonomous web search and summarization
- Automatic common-point discovery across fetched data (shared CVEs, domains, IPs, URLs, MITRE IDs, and key terms)
- Reactive animated dashboard UI (themed command center, timeline charts, progress workflows, toasts/activity log)
- Keyword monitoring (user-provided feeds)
- Threat-actor profiling
- MITRE ATT&CK keyword mapping
- Leak fingerprint matching (hash-to-hash comparison)
- Crypto wallet clustering
- Knowledge-graph visualization
- Optional Neo4j graph persistence
- PDF intelligence brief generation

## Important safety and legal note

This project intentionally does **not** implement covert or intrusive collection:

- No forced Tor traffic rerouting
- No active `.onion` crawling/scraping
- No direct leak-database harvesting

High-risk modules are represented as guarded placeholders so the system stays compliant by default.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Windows one-click startup:

```bat
start_osint_agent.bat
```

## Live feed connectors

In the `Ingestion` tab, use the **Live feed connectors** section to pull:

- RSS/Atom feeds (default CISA RSS URLs and optional custom URLs)
- NVD CVEs via `services.nvd.nist.gov` API
- CISA Known Exploited Vulnerabilities (KEV) JSON feed
- Optional public web-page scraping from user-provided URLs (with `robots.txt` respect toggle)

The fetched data is normalized into the existing `events_df` and `keyword_feed_df` datasets.
The dashboard also auto-detects common points across fetched records to help correlation.

Optional environment variable:

- `NVD_API_KEY` (recommended for higher NVD API rate limits)

Web scraping connector behavior:

- Accepts only user-provided `http(s)` URLs
- Extracts visible page text and metadata
- Supports optional same-domain link following with crawl limits
- Supports optional `robots.txt` enforcement, with an explicit UI toggle to ignore when needed
- Auto-detects common points in scraped content

## Custom AI research agent

In the dashboard `AI Research Agent` tab:

- Enter a research prompt
- Configure query count, results per query, and scrape depth
- Choose search sources (`DuckDuckGo` and/or `Wikipedia`)
- Run autonomous collection and get:
  - generated sub-queries
  - source table
  - optional scraped page excerpts
  - auto-detected common points
  - synthesized summary and key findings
- Optional auto-expansion: when needed, the agent can generate follow-up searches from discovered common points.

## Reactive UI features

- Animated command-center header with live readiness metrics
- Ingestion telemetry line chart (events/feed over time)
- Progress/status workflows for:
  - live feed fetch
  - web scraping
  - full analysis
  - AI research
  - PDF brief generation
- Sidebar activity log with recent actions
- Optional `Fun UI mode` toggle for animated delays and celebratory effects

## CSV schemas

### `events.csv`

Required columns:

- `event_id`
- `timestamp`
- `source`
- `actor`
- `description`
- `indicator_type`
- `indicator_value`
- `wallet`

### `keyword_feed.csv`

Required columns:

- `timestamp`
- `source`
- `content`

### `transactions.csv`

Required columns:

- `tx_hash`
- `from_wallet`
- `to_wallet`
- `amount`
- `timestamp`

### `asset_hashes.csv` and `observed_hashes.csv`

Required column in each:

- `value` (plaintext or SHA-256 hash)

## Neo4j setup (optional)

Set environment variables:

- `NEO4J_URI` (example: `bolt://localhost:7687`)
- `NEO4J_USER`
- `NEO4J_PASSWORD`

Then use the Neo4j push button in the dashboard.
