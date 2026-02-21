from dataclasses import dataclass
from typing import Optional


@dataclass
class EventRecord:
    event_id: str
    timestamp: str
    source: str
    actor: str
    description: str
    indicator_type: str
    indicator_value: str
    wallet: Optional[str] = None


@dataclass
class KeywordHit:
    timestamp: str
    source: str
    content: str
    keyword: str


@dataclass
class MitreHit:
    event_id: str
    actor: str
    keyword: str
    tactic: str
    technique_id: str
    technique_name: str

