from __future__ import annotations

import pandas as pd


def load_demo_events() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "event_id": "E-1001",
                "timestamp": "2026-02-20T11:10:00Z",
                "source": "public_forum",
                "actor": "GhostNova",
                "description": "Phishing lure delivered with credential harvesting kit and C2 callback.",
                "indicator_type": "domain",
                "indicator_value": "signin-check-auth[.]com",
                "wallet": "bc1qdemo001",
            },
            {
                "event_id": "E-1002",
                "timestamp": "2026-02-20T15:50:00Z",
                "source": "paste_site",
                "actor": "GhostNova",
                "description": "Ransom negotiation note mentions exfiltration and data encryption.",
                "indicator_type": "hash",
                "indicator_value": "a9f231d1e09f0ea7d3f4a2f2dd9f7f6c5ea1f46377182ec5f6f9b7d5a1d0e001",
                "wallet": "bc1qdemo002",
            },
            {
                "event_id": "E-1003",
                "timestamp": "2026-02-21T02:01:00Z",
                "source": "incident_report",
                "actor": "RedHydra",
                "description": "Lateral movement observed via remote services and scheduled task persistence.",
                "indicator_type": "ip",
                "indicator_value": "185.199.110.153",
                "wallet": "",
            },
        ]
    )


def load_demo_keyword_feed() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "timestamp": "2026-02-20T10:00:00Z",
                "source": "forum",
                "content": "New phishing panel with full credential support.",
            },
            {
                "timestamp": "2026-02-20T17:20:00Z",
                "source": "chat_export",
                "content": "Data exfiltration complete, waiting for payment.",
            },
            {
                "timestamp": "2026-02-21T08:05:00Z",
                "source": "paste",
                "content": "Noisy scanner traffic only.",
            },
        ]
    )


def load_demo_transactions() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "tx_hash": "tx001",
                "from_wallet": "bc1qdemo001",
                "to_wallet": "bc1qmix001",
                "amount": 1.2,
                "timestamp": "2026-02-20T11:30:00Z",
            },
            {
                "tx_hash": "tx001",
                "from_wallet": "bc1qdemo002",
                "to_wallet": "bc1qmix001",
                "amount": 0.8,
                "timestamp": "2026-02-20T11:30:00Z",
            },
            {
                "tx_hash": "tx002",
                "from_wallet": "bc1qmix001",
                "to_wallet": "bc1qout002",
                "amount": 1.9,
                "timestamp": "2026-02-20T12:15:00Z",
            },
        ]
    )


def load_demo_asset_hashes() -> pd.DataFrame:
    return pd.DataFrame([{"value": "employee1@contoso.com"}, {"value": "Acme-Prod-Token-01"}])


def load_demo_observed_hashes() -> pd.DataFrame:
    return pd.DataFrame([{"value": "employee1@contoso.com"}, {"value": "unknown-sample"}])

