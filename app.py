from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from osint_agent.agent import OSINTResearchAgent
from osint_agent.config import Settings
from osint_agent.modules.graph_ops import graph_to_plotly
from osint_agent.modules.high_risk import (
    dark_web_monitor_notice,
    onion_service_intelligence_notice,
    tor_reroute_notice,
)
from osint_agent.modules.live_feeds import fetch_live_sources, fetch_web_scrape_sources
from osint_agent.modules.neo4j_store import push_graph_to_neo4j
from osint_agent.modules.pdf_brief import generate_pdf_brief
from osint_agent.modules.research_agent import AutonomousResearchAgent
from osint_agent.sample_data import (
    load_demo_asset_hashes,
    load_demo_events,
    load_demo_keyword_feed,
    load_demo_observed_hashes,
    load_demo_transactions,
)


def _empty_df(columns: list[str]) -> pd.DataFrame:
    return pd.DataFrame(columns=columns)


def _read_uploaded_csv(uploaded_file, required_cols: list[str]) -> tuple[pd.DataFrame, str]:
    if uploaded_file is None:
        return _empty_df(required_cols), ""
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as exc:
        return _empty_df(required_cols), f"Failed to read CSV: {exc}"

    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        return _empty_df(required_cols), f"Missing required columns: {', '.join(missing)}"
    return df, ""


def _init_state() -> None:
    st.session_state.setdefault("events_df", _empty_df(["event_id", "timestamp", "source", "actor", "description", "indicator_type", "indicator_value", "wallet"]))
    st.session_state.setdefault("keyword_feed_df", _empty_df(["timestamp", "source", "content"]))
    st.session_state.setdefault("tx_df", _empty_df(["tx_hash", "from_wallet", "to_wallet", "amount", "timestamp"]))
    st.session_state.setdefault("asset_hashes_df", _empty_df(["value"]))
    st.session_state.setdefault("observed_hashes_df", _empty_df(["value"]))
    st.session_state.setdefault("keywords_text", "phishing, credential, exfiltration, ransom, c2, lateral movement")
    st.session_state.setdefault("result", None)
    st.session_state.setdefault("research_prompt_text", "")
    st.session_state.setdefault("research_report", None)


def _load_demo() -> None:
    st.session_state["events_df"] = load_demo_events()
    st.session_state["keyword_feed_df"] = load_demo_keyword_feed()
    st.session_state["tx_df"] = load_demo_transactions()
    st.session_state["asset_hashes_df"] = load_demo_asset_hashes()
    st.session_state["observed_hashes_df"] = load_demo_observed_hashes()


def _clear_all() -> None:
    st.session_state["events_df"] = _empty_df(["event_id", "timestamp", "source", "actor", "description", "indicator_type", "indicator_value", "wallet"])
    st.session_state["keyword_feed_df"] = _empty_df(["timestamp", "source", "content"])
    st.session_state["tx_df"] = _empty_df(["tx_hash", "from_wallet", "to_wallet", "amount", "timestamp"])
    st.session_state["asset_hashes_df"] = _empty_df(["value"])
    st.session_state["observed_hashes_df"] = _empty_df(["value"])
    st.session_state["result"] = None
    st.session_state["research_prompt_text"] = ""
    st.session_state["research_report"] = None


def _merge_events(current: pd.DataFrame, incoming: pd.DataFrame) -> pd.DataFrame:
    if incoming is None or incoming.empty:
        return current
    if current is None or current.empty:
        return incoming.drop_duplicates(subset=["event_id"]).reset_index(drop=True)
    out = pd.concat([current, incoming], ignore_index=True)
    return out.drop_duplicates(subset=["event_id"]).reset_index(drop=True)


def _merge_keyword_feed(current: pd.DataFrame, incoming: pd.DataFrame) -> pd.DataFrame:
    if incoming is None or incoming.empty:
        return current
    if current is None or current.empty:
        return incoming.drop_duplicates(subset=["timestamp", "source", "content"]).reset_index(drop=True)
    out = pd.concat([current, incoming], ignore_index=True)
    return out.drop_duplicates(subset=["timestamp", "source", "content"]).reset_index(drop=True)


def main() -> None:
    load_dotenv()
    settings = Settings.from_env()
    agent = OSINTResearchAgent()

    st.set_page_config(page_title="OSINT Research Agent", layout="wide")
    _init_state()

    st.title("OSINT Research Agent Dashboard")
    st.caption("Compliance-first intelligence workflow for lawful, user-provided datasets.")
    st.warning(
        "This build does not include forced Tor rerouting, active onion crawling, or direct leak-database harvesting."
    )

    with st.sidebar:
        st.header("Workspace")
        if st.button("Load Demo Data"):
            _load_demo()
            st.success("Demo data loaded.")
        if st.button("Clear All Data"):
            _clear_all()
            st.success("Session data cleared.")
        st.text_input("Keywords (comma-separated)", key="keywords_text")

    tabs = st.tabs(
        [
            "Ingestion",
            "Analysis Results",
            "Actor + MITRE",
            "Wallet + Graph",
            "PDF Brief",
            "AI Research Agent",
            "High-Risk Modules",
        ]
    )

    with tabs[0]:
        st.subheader("Upload datasets")
        col1, col2 = st.columns(2)

        with col1:
            events_file = st.file_uploader("events.csv", type=["csv"])
            events_df, err = _read_uploaded_csv(
                events_file,
                ["event_id", "timestamp", "source", "actor", "description", "indicator_type", "indicator_value", "wallet"],
            )
            if events_file is not None:
                if err:
                    st.error(err)
                else:
                    st.session_state["events_df"] = events_df
                    st.success(f"Loaded {len(events_df)} events.")

            feed_file = st.file_uploader("keyword_feed.csv", type=["csv"])
            feed_df, err = _read_uploaded_csv(feed_file, ["timestamp", "source", "content"])
            if feed_file is not None:
                if err:
                    st.error(err)
                else:
                    st.session_state["keyword_feed_df"] = feed_df
                    st.success(f"Loaded {len(feed_df)} feed rows.")

            tx_file = st.file_uploader("transactions.csv", type=["csv"])
            tx_df, err = _read_uploaded_csv(tx_file, ["tx_hash", "from_wallet", "to_wallet", "amount", "timestamp"])
            if tx_file is not None:
                if err:
                    st.error(err)
                else:
                    st.session_state["tx_df"] = tx_df
                    st.success(f"Loaded {len(tx_df)} transactions.")

        with col2:
            asset_file = st.file_uploader("asset_hashes.csv", type=["csv"])
            assets_df, err = _read_uploaded_csv(asset_file, ["value"])
            if asset_file is not None:
                if err:
                    st.error(err)
                else:
                    st.session_state["asset_hashes_df"] = assets_df
                    st.success(f"Loaded {len(assets_df)} asset fingerprints.")

            observed_file = st.file_uploader("observed_hashes.csv", type=["csv"])
            observed_df, err = _read_uploaded_csv(observed_file, ["value"])
            if observed_file is not None:
                if err:
                    st.error(err)
                else:
                    st.session_state["observed_hashes_df"] = observed_df
                    st.success(f"Loaded {len(observed_df)} observed fingerprints.")

            st.markdown("Required CSV schemas are documented in `README.md`.")

        st.divider()
        st.subheader("Live feed connectors")
        st.caption("Fetch from legal/public sources: RSS, NVD API, and CISA advisories (KEV).")
        live_col1, live_col2 = st.columns(2)

        with live_col1:
            lookback_days = st.number_input(
                "Lookback days", min_value=1, max_value=30, value=7, step=1, key="live_lookback_days"
            )
            max_rss_items = st.number_input(
                "Max RSS items per feed",
                min_value=10,
                max_value=500,
                value=100,
                step=10,
                key="live_max_rss_items",
            )
            nvd_max_results = st.number_input(
                "NVD max CVEs",
                min_value=10,
                max_value=2000,
                value=200,
                step=10,
                key="live_nvd_max_results",
            )
            include_default_rss = st.checkbox("Include default CISA RSS URLs", value=True)

        with live_col2:
            custom_rss = st.text_area(
                "Custom RSS URLs (one per line)",
                value="",
                height=120,
                help="Example: https://www.cisa.gov/news.xml",
            )
            nvd_api_key = st.text_input("NVD API key (optional)", value="", type="password")
            fetch_nvd = st.checkbox("Fetch NVD CVEs", value=True)
            fetch_cisa = st.checkbox("Fetch CISA KEV", value=True)

        fetch_cols = st.columns(4)
        do_fetch_all = fetch_cols[0].button("Fetch All Live Feeds")
        do_fetch_rss = fetch_cols[1].button("Fetch RSS Only")
        do_fetch_nvd = fetch_cols[2].button("Fetch NVD Only")
        do_fetch_cisa = fetch_cols[3].button("Fetch CISA Only")

        if do_fetch_all or do_fetch_rss or do_fetch_nvd or do_fetch_cisa:
            rss_urls = [line.strip() for line in custom_rss.splitlines() if line.strip()]
            use_rss = do_fetch_all or do_fetch_rss or do_fetch_cisa
            result = fetch_live_sources(
                rss_urls=rss_urls if use_rss else [],
                include_default_rss=include_default_rss and use_rss,
                lookback_days=int(lookback_days),
                max_rss_items_per_feed=int(max_rss_items),
                fetch_nvd=do_fetch_nvd or do_fetch_all,
                nvd_max_results=int(nvd_max_results),
                nvd_api_key=nvd_api_key.strip() or None,
                fetch_cisa=do_fetch_cisa or do_fetch_all,
            )

            before_events = len(st.session_state["events_df"])
            before_feed = len(st.session_state["keyword_feed_df"])
            st.session_state["events_df"] = _merge_events(st.session_state["events_df"], result.events_df)
            st.session_state["keyword_feed_df"] = _merge_keyword_feed(
                st.session_state["keyword_feed_df"], result.keyword_feed_df
            )
            after_events = len(st.session_state["events_df"])
            after_feed = len(st.session_state["keyword_feed_df"])

            st.success(
                f"Live fetch complete. Events +{after_events - before_events}, keyword feed +{after_feed - before_feed}."
            )
            if result.errors:
                for err in result.errors:
                    st.warning(err)
            if not result.raw_items_df.empty:
                st.markdown("Fetched RSS items preview")
                st.dataframe(result.raw_items_df.head(20), width="stretch")

        st.divider()
        st.subheader("Optional public web scraping")
        st.caption("Scrape user-provided public URLs and ingest extracted text into events and keyword feed.")
        st.info("Use only lawful targets. Respect website terms and robots rules.")

        scrape_col1, scrape_col2 = st.columns(2)
        with scrape_col1:
            web_urls_text = st.text_area(
                "Web URLs to scrape (one per line)",
                value="",
                height=110,
                help="Example: https://www.cisa.gov/news-events/cybersecurity-advisories",
            )
            scrape_max_pages = st.number_input(
                "Max pages to scrape", min_value=1, max_value=200, value=20, step=1, key="scrape_max_pages"
            )
            scrape_max_chars = st.number_input(
                "Max text chars per page",
                min_value=500,
                max_value=20000,
                value=4000,
                step=500,
                key="scrape_max_chars",
            )

        with scrape_col2:
            scrape_follow_links = st.checkbox("Follow same-domain links", value=False)
            scrape_same_domain_only = st.checkbox("Restrict to same domain", value=True)
            scrape_respect_robots = st.checkbox("Respect robots.txt", value=True)
            scrape_max_links_per_page = st.number_input(
                "Max discovered links per page",
                min_value=1,
                max_value=50,
                value=8,
                step=1,
                key="scrape_max_links_per_page",
            )
            scrape_timeout = st.number_input(
                "HTTP timeout (seconds)",
                min_value=5,
                max_value=90,
                value=25,
                step=5,
                key="scrape_http_timeout_sec",
            )

        do_scrape = st.button("Scrape Web URLs")
        if do_scrape:
            web_urls = [line.strip() for line in web_urls_text.splitlines() if line.strip()]
            if not web_urls:
                st.warning("Provide at least one URL to scrape.")
            else:
                scrape_result = fetch_web_scrape_sources(
                    urls=web_urls,
                    follow_same_domain_links=scrape_follow_links,
                    same_domain_only=scrape_same_domain_only,
                    respect_robots_txt=scrape_respect_robots,
                    max_pages=int(scrape_max_pages),
                    max_links_per_page=int(scrape_max_links_per_page),
                    max_chars=int(scrape_max_chars),
                    timeout=int(scrape_timeout),
                )
                before_events = len(st.session_state["events_df"])
                before_feed = len(st.session_state["keyword_feed_df"])
                st.session_state["events_df"] = _merge_events(st.session_state["events_df"], scrape_result.events_df)
                st.session_state["keyword_feed_df"] = _merge_keyword_feed(
                    st.session_state["keyword_feed_df"], scrape_result.keyword_feed_df
                )
                after_events = len(st.session_state["events_df"])
                after_feed = len(st.session_state["keyword_feed_df"])

                st.success(
                    f"Web scrape complete. Events +{after_events - before_events}, keyword feed +{after_feed - before_feed}."
                )
                if scrape_result.errors:
                    for err in scrape_result.errors:
                        st.warning(err)
                if not scrape_result.raw_items_df.empty:
                    st.markdown("Scraped page preview")
                    st.dataframe(scrape_result.raw_items_df.head(20), width="stretch")

        st.divider()
        run = st.button("Run Analysis", type="primary")
        if run:
            keywords = [k.strip() for k in st.session_state.get("keywords_text", "").split(",") if k.strip()]
            result = agent.analyze(
                events_df=st.session_state["events_df"],
                keyword_feed_df=st.session_state["keyword_feed_df"],
                keywords=keywords,
                tx_df=st.session_state["tx_df"],
                asset_hashes_df=st.session_state["asset_hashes_df"],
                observed_hashes_df=st.session_state["observed_hashes_df"],
            )
            st.session_state["result"] = result
            st.success("Analysis complete.")

        st.write("Current events preview")
        st.dataframe(st.session_state["events_df"].head(10), width="stretch")

    with tabs[1]:
        st.subheader("Analysis outputs")
        result = st.session_state.get("result")
        if result is None:
            st.info("Run analysis first.")
        else:
            metric_cols = st.columns(5)
            metric_cols[0].metric("Events", len(st.session_state["events_df"]))
            metric_cols[1].metric("Keyword Hits", len(result.keyword_hits))
            metric_cols[2].metric("MITRE Hits", len(result.mitre_hits))
            metric_cols[3].metric("Wallet Clusters", result.wallet_clusters["cluster_id"].nunique() if not result.wallet_clusters.empty else 0)
            metric_cols[4].metric("Leak Matches", len(result.leak_matches))

            st.markdown("Keyword hits")
            st.dataframe(result.keyword_hits, width="stretch")
            st.markdown("Leak fingerprint matches")
            st.dataframe(result.leak_matches, width="stretch")

    with tabs[2]:
        st.subheader("Threat-actor profiling and ATT&CK mapping")
        result = st.session_state.get("result")
        if result is None:
            st.info("Run analysis first.")
        else:
            left, right = st.columns(2)
            with left:
                st.markdown("Actor profiles")
                st.dataframe(result.actor_profiles, width="stretch")
            with right:
                st.markdown("MITRE ATT&CK hits")
                st.dataframe(result.mitre_hits, width="stretch")
                if not result.mitre_hits.empty:
                    tactic_counts = result.mitre_hits.groupby("tactic").size().reset_index(name="count")
                    st.bar_chart(tactic_counts, x="tactic", y="count")

    with tabs[3]:
        st.subheader("Crypto wallet clustering and graph visualization")
        result = st.session_state.get("result")
        if result is None:
            st.info("Run analysis first.")
        else:
            st.markdown("Wallet clusters")
            st.dataframe(result.wallet_clusters, width="stretch")

            fig = graph_to_plotly(result.knowledge_graph)
            st.plotly_chart(fig, width="stretch")

            st.divider()
            st.markdown("Optional: push graph to Neo4j")
            if st.button("Push Graph to Neo4j"):
                try:
                    nodes, rels = push_graph_to_neo4j(
                        result.knowledge_graph,
                        uri=settings.neo4j_uri,
                        user=settings.neo4j_user,
                        password=settings.neo4j_password,
                    )
                    st.success(f"Graph pushed to Neo4j: {nodes} nodes, {rels} relationships.")
                except Exception as exc:
                    st.error(str(exc))

    with tabs[4]:
        st.subheader("PDF intelligence brief")
        result = st.session_state.get("result")
        if result is None:
            st.info("Run analysis first.")
        else:
            summary_default = (
                f"Total events: {len(st.session_state['events_df'])}. "
                f"Keyword hits: {len(result.keyword_hits)}. "
                f"MITRE mappings: {len(result.mitre_hits)}. "
                f"Wallet clusters: {result.wallet_clusters['cluster_id'].nunique() if not result.wallet_clusters.empty else 0}. "
                f"Leak matches: {len(result.leak_matches)}."
            )
            summary_text = st.text_area("Executive summary text", value=summary_default, height=120)

            if st.button("Generate PDF Brief"):
                ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                output_path = Path("outputs") / f"intelligence_brief_{ts}.pdf"
                generated = generate_pdf_brief(
                    output_path=str(output_path),
                    summary_text=summary_text,
                    actor_profiles=result.actor_profiles,
                    mitre_hits=result.mitre_hits,
                    keyword_hits=result.keyword_hits,
                    wallet_clusters=result.wallet_clusters,
                    leak_matches=result.leak_matches,
                )
                st.success(f"Brief generated: {generated}")
                with open(generated, "rb") as f:
                    st.download_button(
                        label="Download Brief",
                        data=f.read(),
                        file_name=Path(generated).name,
                        mime="application/pdf",
                    )

    with tabs[5]:
        st.subheader("Custom AI Research Agent")
        st.caption("Enter a prompt. The agent generates search queries, collects sources, optionally scrapes pages, and summarizes findings.")

        prompt = st.text_area(
            "Research prompt",
            key="research_prompt_text",
            height=130,
            placeholder="Example: Summarize the latest ransomware trends affecting healthcare organizations and notable CVEs.",
        )

        ra_col1, ra_col2 = st.columns(2)
        with ra_col1:
            ra_max_queries = st.number_input(
                "Max generated queries", min_value=1, max_value=8, value=4, step=1, key="ra_max_queries"
            )
            ra_results_per_query = st.number_input(
                "Results per query", min_value=1, max_value=10, value=5, step=1, key="ra_results_per_query"
            )
            ra_max_total = st.number_input(
                "Max total sources", min_value=5, max_value=80, value=20, step=1, key="ra_max_total_sources"
            )
            ra_max_pages = st.number_input(
                "Max pages to scrape", min_value=0, max_value=40, value=10, step=1, key="ra_max_pages"
            )
        with ra_col2:
            ra_timeout = st.number_input(
                "HTTP timeout (seconds)",
                min_value=5,
                max_value=90,
                value=25,
                step=5,
                key="ra_http_timeout_sec",
            )
            ra_use_ddg = st.checkbox("Use DuckDuckGo web search", value=True)
            ra_use_wiki = st.checkbox("Use Wikipedia search", value=True)
            ra_scrape_pages = st.checkbox("Scrape collected source pages", value=True)

        if st.button("Run AI Research"):
            if not prompt.strip():
                st.warning("Enter a research prompt first.")
            elif not ra_use_ddg and not ra_use_wiki:
                st.warning("Enable at least one search source.")
            else:
                research_agent = AutonomousResearchAgent(timeout=int(ra_timeout))
                report = research_agent.run(
                    prompt=prompt.strip(),
                    max_queries=int(ra_max_queries),
                    max_results_per_query=int(ra_results_per_query),
                    max_total_results=int(ra_max_total),
                    max_pages_to_scrape=int(ra_max_pages),
                    include_duckduckgo=bool(ra_use_ddg),
                    include_wikipedia=bool(ra_use_wiki),
                    scrape_pages=bool(ra_scrape_pages) and int(ra_max_pages) > 0,
                )
                st.session_state["research_report"] = report
                st.success("AI research run completed.")

        report = st.session_state.get("research_report")
        if report is None:
            st.info("Run AI Research to generate a report.")
        else:
            st.markdown("Generated Queries")
            if report.queries:
                st.code("\n".join(report.queries))
            else:
                st.write("No queries generated.")

            st.markdown("Research Summary")
            st.write(report.summary)

            st.markdown("Key Findings")
            if report.findings:
                for idx, finding in enumerate(report.findings, start=1):
                    st.write(f"{idx}. {finding}")
            else:
                st.write("No findings extracted.")

            metric_cols = st.columns(3)
            metric_cols[0].metric("Sources", len(report.sources_df))
            metric_cols[1].metric("Scraped Pages", len(report.pages_df))
            metric_cols[2].metric("Warnings", len(report.errors))

            st.markdown("Source Results")
            st.dataframe(report.sources_df, width="stretch")

            if not report.pages_df.empty:
                st.markdown("Scraped Page Excerpts")
                st.dataframe(report.pages_df.head(20), width="stretch")

            if report.errors:
                st.markdown("Warnings / Errors")
                for err in report.errors:
                    st.warning(err)

    with tabs[6]:
        st.subheader("High-risk module status")
        st.write(f"Tor traffic rerouting: {tor_reroute_notice(settings)}")
        st.write(f"Onion service intelligence: {onion_service_intelligence_notice(settings)}")
        st.write(f"Dark-web monitoring: {dark_web_monitor_notice(settings)}")
        st.info("For legal and safety reasons, these features remain non-operational placeholders in this build.")


if __name__ == "__main__":
    main()
