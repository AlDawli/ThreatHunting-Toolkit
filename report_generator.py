"""
core/report_generator.py
─────────────────────────
Generates a professional PDF threat-intelligence report from
the database's search history and IOC watchlist.

Uses fpdf2 (FPDF2 library). Install: pip install fpdf2
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fpdf import FPDF, XPos, YPos

from config.settings import EXPORTS_DIR


def _s(text: str) -> str:
    """Strip characters outside latin-1 so Courier can render them."""
    return (
        str(text)
        .replace('\u2500', '-').replace('\u25ba', '>').replace('\u2014', '--')
        .replace('\u2013', '-').replace('\u25b6', '>').replace('\u2019', "'")
        .encode('latin-1', errors='replace').decode('latin-1')
    )


# ── Colour palette (R, G, B) ──────────────────────────────────────────────────
C_BG_DARK    = (10,  14,  24)
C_BG_MID     = (18,  26,  44)
C_ACCENT     = (0,   210, 140)   # teal-green
C_DANGER     = (220, 50,  70)
C_WARNING    = (230, 170, 30)
C_OK         = (40,  180, 100)
C_LIGHT_TEXT = (220, 230, 240)
C_MUTED      = (110, 130, 155)
C_WHITE      = (255, 255, 255)
C_BLACK      = (10,  10,  10)


def _verdict_color(verdict: str) -> tuple[int, int, int]:
    return {
        "MALICIOUS":  C_DANGER,
        "SUSPICIOUS": C_WARNING,
        "CLEAN":      C_OK,
    }.get(verdict.upper(), C_MUTED)


# ── PDF class ─────────────────────────────────────────────────────────────────

class ThreatReport(FPDF):

    def header(self):
        # Dark header bar
        self.set_fill_color(*C_BG_DARK)
        self.rect(0, 0, 210, 28, style="F")

        self.set_xy(8, 6)
        self.set_font("Courier", "B", 15)
        self.set_text_color(*C_ACCENT)
        self.cell(0, 8, _s("THREAT HUNTING TOOLKIT"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_x(8)
        self.set_font("Courier", "", 8)
        self.set_text_color(*C_MUTED)
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.cell(0, 6, f"Intelligence Report  |  Generated: {ts}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(4)

    def footer(self):
        self.set_y(-13)
        self.set_font("Courier", "", 7)
        self.set_text_color(*C_MUTED)
        self.cell(0, 8,
                  _s(f"Page {self.page_no()}  |  CONFIDENTIAL - FOR INTERNAL USE ONLY"),
                  align="C")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def section_title(self, title: str) -> None:
        self.set_fill_color(*C_BG_MID)
        self.set_text_color(*C_ACCENT)
        self.set_font("Courier", "B", 11)
        self.cell(0, 9, _s(f"  {title}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT,
                  fill=True)
        self.ln(2)

    def kv_row(self, label: str, value: str,
               value_color: tuple = C_BLACK) -> None:
        self.set_font("Courier", "B", 8)
        self.set_text_color(*C_MUTED)
        self.cell(45, 6, _s(label.upper()), border="B")
        self.set_font("Courier", "", 8)
        self.set_text_color(*value_color)
        self.cell(0, 6, _s(str(value)[:90]), border="B",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def colored_badge(self, text: str, color: tuple) -> None:
        self.set_fill_color(*color)
        self.set_text_color(*C_WHITE)
        self.set_font("Courier", "B", 9)
        self.cell(len(text) * 3.2 + 6, 7, f" {text} ", fill=True)


# ── Public entry point ────────────────────────────────────────────────────────

def generate_report(
    searches: list[dict],
    iocs:     list[dict],
    filename: str | None = None,
) -> Path:
    """
    Build and save a PDF report.

    Parameters
    ----------
    searches : rows from the ``searches`` table (history)
    iocs     : rows from the ``iocs`` table (watchlist)
    filename : optional output filename; auto-generated if omitted

    Returns
    -------
    Path  to the saved PDF file.
    """
    pdf = ThreatReport(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)

    # ── Summary stats ─────────────────────────────────────────────────────────
    pdf.section_title(_s("EXECUTIVE SUMMARY"))

    total      = len(searches)
    malicious  = sum(1 for s in searches if s.get("verdict") == "MALICIOUS")
    suspicious = sum(1 for s in searches if s.get("verdict") == "SUSPICIOUS")
    clean      = sum(1 for s in searches if s.get("verdict") == "CLEAN")

    pdf.set_font("Courier", "", 9)
    stats = [
        ("Total Searches",       str(total),     C_BLACK),
        ("Malicious Detections", str(malicious),  C_DANGER),
        ("Suspicious",           str(suspicious), C_WARNING),
        ("Clean",                str(clean),      C_OK),
        ("IOCs in Watchlist",    str(len(iocs)),  C_BLACK),
    ]
    for label, val, col in stats:
        pdf.kv_row(label, val, col)
    pdf.ln(5)

    # ── IOC Watchlist ─────────────────────────────────────────────────────────
    if iocs:
        pdf.section_title(_s("IOC WATCHLIST"))
        _table_header(pdf, ["IOC", "TYPE", "TAGS", "ADDED"])
        for ioc in iocs[:50]:
            _table_row(pdf, [
                ioc.get("ioc", "")[:50],
                ioc.get("ioc_type", "").upper(),
                ioc.get("tags", "")[:30],
                ioc.get("added_at", "")[:10],
            ])
        pdf.ln(5)

    # ── Search History ────────────────────────────────────────────────────────
    if searches:
        pdf.section_title(_s("SEARCH HISTORY"))
        _table_header(pdf, ["IOC / Query", "TYPE", "VERDICT", "MAL", "SUS", "DATE"])

        for s in searches[:80]:
            verdict = s.get("verdict", "UNKNOWN")
            vcol    = _verdict_color(verdict)
            _table_row(pdf, [
                s.get("query", "")[:44],
                s.get("ioc_type", "").upper()[:10],
                verdict,
                str(s.get("malicious_count",  0)),
                str(s.get("suspicious_count", 0)),
                s.get("timestamp", "")[:10],
            ], verdict_col=vcol)

        pdf.ln(5)

    # ── Malicious detail cards ────────────────────────────────────────────────
    mal_searches = [s for s in searches if s.get("verdict") == "MALICIOUS"]
    if mal_searches:
        pdf.add_page()
        pdf.section_title(_s("MALICIOUS IOC DETAIL"))

        for s in mal_searches[:20]:
            pdf.set_fill_color(*C_BG_MID)
            pdf.set_font("Courier", "B", 9)
            pdf.set_text_color(*C_ACCENT)
            pdf.cell(0, 7, _s(f"  > {s.get('query', '')}"),
                     fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.kv_row("Type",     _s(s.get("ioc_type","?").upper()))
            pdf.kv_row("Verdict",  _s(s.get("verdict","?")),  C_DANGER)
            pdf.kv_row("Malicious",_s(str(s.get("malicious_count",0))), C_DANGER)
            pdf.kv_row(_s("Suspicious"),_s(str(s.get("suspicious_count",0))), C_WARNING)
            pdf.kv_row("Scanned",  _s(s.get("timestamp","")[:19]))
            pdf.ln(4)

    # ── Save ──────────────────────────────────────────────────────────────────
    if not filename:
        filename = f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    out = EXPORTS_DIR / filename
    pdf.output(str(out))
    return out


# ── Table helpers ─────────────────────────────────────────────────────────────

_COL_WIDTHS = [74, 22, 24, 14, 14, 22]   # matches 6-column history table
_COL_WIDTHS_4 = [80, 22, 40, 28]         # 4-column watchlist table


def _table_header(pdf: FPDF, cols: list[str]) -> None:
    widths = _COL_WIDTHS_4 if len(cols) == 4 else _COL_WIDTHS
    pdf.set_fill_color(*C_BG_DARK)
    pdf.set_text_color(*C_LIGHT_TEXT)
    pdf.set_font("Courier", "B", 8)
    for col, w in zip(cols, widths):
        pdf.cell(w, 7, _s(f" {col}"), border=1, fill=True)
    pdf.ln()


def _table_row(pdf: FPDF, cols: list[str],
               verdict_col: tuple = C_BLACK) -> None:
    widths = _COL_WIDTHS_4 if len(cols) == 4 else _COL_WIDTHS
    pdf.set_font("Courier", "", 7)
    for i, (col, w) in enumerate(zip(cols, widths)):
        # Colour the VERDICT column
        color = verdict_col if (len(cols) == 6 and i == 2) else C_BLACK
        pdf.set_text_color(*color)
        pdf.cell(w, 6, _s(f" {col}"), border=1)
    pdf.set_text_color(*C_BLACK)
    pdf.ln()
