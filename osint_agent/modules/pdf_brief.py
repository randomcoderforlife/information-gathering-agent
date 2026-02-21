from __future__ import annotations

from pathlib import Path
from datetime import datetime
import pandas as pd
from fpdf import FPDF


class BriefPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, "OSINT Intelligence Brief", ln=1)
        self.set_font("Helvetica", "", 9)
        self.cell(0, 6, f"Generated: {datetime.utcnow().isoformat()}Z", ln=1)
        self.ln(2)


def _render_table(pdf: FPDF, title: str, df: pd.DataFrame, max_rows: int = 12) -> None:
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, title, ln=1)

    if df.empty:
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 6, "No data available.")
        pdf.ln(2)
        return

    pdf.set_font("Helvetica", "", 8)
    view = df.head(max_rows).astype(str)
    headers = list(view.columns)
    line = " | ".join(headers)
    pdf.multi_cell(0, 5, line)
    pdf.multi_cell(0, 5, "-" * min(120, len(line)))
    for _, row in view.iterrows():
        pdf.multi_cell(0, 5, " | ".join([row[col] for col in headers]))
    pdf.ln(2)


def generate_pdf_brief(
    output_path: str,
    summary_text: str,
    actor_profiles: pd.DataFrame,
    mitre_hits: pd.DataFrame,
    keyword_hits: pd.DataFrame,
    wallet_clusters: pd.DataFrame,
    leak_matches: pd.DataFrame,
) -> str:
    pdf = BriefPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Executive Summary", ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 6, summary_text)
    pdf.ln(2)

    _render_table(pdf, "Threat-Actor Profiles", actor_profiles)
    _render_table(pdf, "MITRE ATT&CK Mapping Hits", mitre_hits)
    _render_table(pdf, "Keyword Monitoring Hits", keyword_hits)
    _render_table(pdf, "Wallet Clusters", wallet_clusters)
    _render_table(pdf, "Leak Fingerprint Matches", leak_matches)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out))
    return str(out)

