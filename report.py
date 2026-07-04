#!/usr/bin/env python3
"""Render an NDJSON findings file into a readable Markdown or HTML report.

Usage:
    python report.py findings.ndjson              # -> findings.md
    python report.py findings.ndjson -f html      # -> findings.html
    python report.py findings.ndjson -o report.md
"""
from __future__ import annotations

import argparse
import html
import json
import os

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_COLOR = {
    "Critical": "#b00020", "High": "#e65100", "Medium": "#f9a825",
    "Low": "#2e7d32", "Info": "#546e7a",
}


def load(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    rows.sort(key=lambda r: (SEV_ORDER.get(r.get("severity"), 9),
                             {"High": 0, "Medium": 1, "Low": 2}.get(
                                 r.get("confidence"), 3)))
    return rows


def to_markdown(rows: list[dict]) -> str:
    out = ["# Vulnerability Findings Report\n"]
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    out.append(f"**Total findings:** {len(rows)}  ")
    out.append(" · ".join(f"{s}: {counts[s]}"
                          for s in SEV_ORDER if s in counts) + "\n")
    for i, r in enumerate(rows, 1):
        out.append(f"\n## {i}. [{r['severity']}] {r['description'][:90]}\n")
        out.append(f"- **File:** `{r.get('file')}`  ")
        out.append(f"- **Lines:** {r.get('lines')}  ")
        out.append(f"- **Type:** {r.get('type', 'code')}  ")
        out.append(f"- **Confidence:** {r.get('confidence')}  ")
        if r.get("cwe"):
            out.append(f"- **CWE:** {r['cwe']}  ")
        v = r.get("verify")
        if v:
            out.append(f"- **Verify:** {v.get('verdict')} — {v.get('reasoning', '')}  ")
        out.append(f"\n**Description**\n\n{r.get('description')}\n")
        out.append(f"**Attack Path**\n\n{r.get('attack_path')}\n")
        out.append(f"**Evidence**\n\n{r.get('evidence')}\n")
        out.append("**Affected Code**\n\n```\n"
                   f"{r.get('affected_code')}\n```\n")
        out.append(f"**Recommendation**\n\n{r.get('recommendation')}\n")
        out.append("\n---")
    return "\n".join(out)


def to_html(rows: list[dict]) -> str:
    def esc(x) -> str:
        return html.escape(str(x or ""))
    cards = []
    for i, r in enumerate(rows, 1):
        color = SEV_COLOR.get(r["severity"], "#555")
        v = r.get("verify") or {}
        vbadge = (f'<span class="v">✓ {esc(v.get("verdict"))}</span>'
                  if v.get("verdict") else "")
        cards.append(f"""
        <div class="card">
          <div class="hd">
            <span class="sev" style="background:{color}">{esc(r['severity'])}</span>
            <span class="conf">confidence: {esc(r.get('confidence'))}</span>
            <span class="conf">{esc(r.get('type', 'code'))}</span>
            {vbadge}
            <span class="file">{esc(r.get('file'))}:{esc(r.get('lines'))}</span>
          </div>
          <h3>{i}. {esc(r.get('description'))[:120]}</h3>
          <p class="lbl">Attack Path</p><p>{esc(r.get('attack_path'))}</p>
          <p class="lbl">Evidence</p><p>{esc(r.get('evidence'))}</p>
          <p class="lbl">Affected Code</p><pre>{esc(r.get('affected_code'))}</pre>
          <p class="lbl">Recommendation</p><p>{esc(r.get('recommendation'))}</p>
          <p class="cwe">{esc(r.get('cwe'))}</p>
        </div>""")
    return f"""<!doctype html><meta charset="utf-8">
<title>Vulnerability Findings</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
 .card{{border:1px solid #ddd;border-radius:10px;padding:1rem 1.25rem;margin:1rem 0;box-shadow:0 1px 3px #0001}}
 .hd{{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;font-size:13px}}
 .sev{{color:#fff;padding:2px 10px;border-radius:20px;font-weight:600}}
 .conf{{color:#555}} .file{{margin-left:auto;font-family:monospace;color:#333}}
 .v{{color:#2e7d32;font-weight:600}}
 .lbl{{font-weight:600;margin:.8rem 0 .2rem;color:#444;font-size:13px;text-transform:uppercase;letter-spacing:.03em}}
 pre{{background:#f6f8fa;padding:.8rem;border-radius:6px;overflow:auto;font-size:13px}}
 .cwe{{color:#888;font-size:12px}}
 h1{{border-bottom:2px solid #eee;padding-bottom:.4rem}}
</style>
<h1>Vulnerability Findings Report</h1>
<p>Total findings: <b>{len(rows)}</b></p>
{''.join(cards)}"""


def _verdict(r: dict) -> str:
    return (r.get("verify") or {}).get("verdict", "") or ""


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Render NDJSON findings to Markdown/HTML, with filters.")
    ap.add_argument("ndjson")
    ap.add_argument("-f", "--format", choices=["md", "html"], default="md")
    ap.add_argument("-o", "--out", default="")
    ap.add_argument("--verdict", default="",
                    help="Keep only findings with this verify verdict "
                         "(e.g. false_positive, true_positive, uncertain)")
    ap.add_argument("--only-fp", action="store_true",
                    help="Shortcut for --verdict false_positive")
    ap.add_argument("--type", default="",
                    help="Keep only this finding type (code / chain / dependency)")
    ap.add_argument("--min-severity", default="",
                    choices=["Critical", "High", "Medium", "Low", "Info"],
                    help="Drop findings below this severity")
    a = ap.parse_args()

    rows = load(a.ndjson)
    total = len(rows)
    want_verdict = "false_positive" if a.only_fp else a.verdict
    if want_verdict:
        rows = [r for r in rows if _verdict(r) == want_verdict]
    if a.type:
        rows = [r for r in rows if r.get("type") == a.type]
    if a.min_severity:
        floor = SEV_ORDER[a.min_severity]
        rows = [r for r in rows if SEV_ORDER.get(r.get("severity"), 9) <= floor]

    body = to_html(rows) if a.format == "html" else to_markdown(rows)
    out = a.out or (os.path.splitext(a.ndjson)[0] +
                    (".html" if a.format == "html" else ".md"))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    filt = f" (filtered from {total})" if len(rows) != total else ""
    print(f"Wrote {out} ({len(rows)} findings{filt})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
