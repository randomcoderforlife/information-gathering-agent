from dataclasses import dataclass
import os


@dataclass
class Settings:
    neo4j_uri: str = ""
    neo4j_user: str = ""
    neo4j_password: str = ""
    allow_high_risk_osint: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            neo4j_uri=os.getenv("NEO4J_URI", "").strip(),
            neo4j_user=os.getenv("NEO4J_USER", "").strip(),
            neo4j_password=os.getenv("NEO4J_PASSWORD", "").strip(),
            allow_high_risk_osint=os.getenv("ALLOW_HIGH_RISK_OSINT", "0").strip() == "1",
        )

