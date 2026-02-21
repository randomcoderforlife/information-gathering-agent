from __future__ import annotations

from osint_agent.config import Settings


class HighRiskFeatureDisabled(RuntimeError):
    pass


def tor_reroute_notice(settings: Settings) -> str:
    if settings.allow_high_risk_osint:
        return (
            "High-risk mode flag is enabled, but forced Tor rerouting is intentionally not implemented "
            "in this compliance-first build."
        )
    return "Forced Tor rerouting is disabled."


def onion_service_intelligence_notice(settings: Settings) -> str:
    if settings.allow_high_risk_osint:
        return (
            "Active onion service crawling is intentionally not implemented in this build. "
            "Only manually collected metadata should be ingested."
        )
    return "Onion service crawling is disabled."


def dark_web_monitor_notice(settings: Settings) -> str:
    if settings.allow_high_risk_osint:
        return (
            "Direct dark-web monitoring connectors are not included. "
            "Use only lawful, user-provided datasets."
        )
    return "Dark-web live monitoring connectors are disabled."

