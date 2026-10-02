#!/usr/bin/env python3
"""Rapport HTML Plumber (format GitLab SAST) au meme style que les rapports Trivy / KICS.

Usage:
    generate_plumber_report.py [gl-sast-report.json] [-j plumber-report.json] [-o report.html]

Le rapport glsast (--glsast) fournit les findings ; le rapport JSON (--output),
optionnel, fournit le Plumber Score, le verdict et les avertissements.
Stdlib uniquement, HTML autonome (CSS/JS inline, aucun CDN).
"""
import argparse
import html
import json
import os
import sys
from datetime import datetime, timezone

DEFAULT_REPORT = "gl-sast-report.json"
DEFAULT_JSON = "plumber-report.json"
DEFAULT_OUT = "plumber-report.html"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
NO_CONTROL = "other"

CSS = """
:root {
  --critical: #c62828; --high: #e65100; --medium: #f9a825; --low: #2e7d32;
  --info: #1565c0; --unknown: #616161; --files: #37474f;
  --score-a: #2e7d32; --score-b: #689f38; --score-c: #f9a825; --score-d: #e65100; --score-e: #c62828;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #212121; }

header { background: #1a237e; color: white; padding: 1.5rem 2rem; }
header h1 { font-size: 1.4rem; font-weight: 600; }
header p { opacity: .7; font-size: .85rem; margin-top: .3rem; }

.summary { display: flex; gap: 1rem; padding: 1.25rem 2rem; background: white; border-bottom: 1px solid #e0e0e0; flex-wrap: wrap; }
.card { flex: 1; min-width: 110px; border-radius: 8px; padding: .9rem 1.25rem; color: white; text-align: center; }
.card .count { font-size: 2.2rem; font-weight: 700; line-height: 1; }
.card .label { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; margin-top: .3rem; opacity: .9; }
.card .sub { font-size: .75rem; margin-top: .2rem; opacity: .85; }
.card-critical { background: var(--critical); }
.card-high     { background: var(--high); }
.card-medium   { background: var(--medium); color: #212121; }
.card-low      { background: var(--low); }
.card-files    { background: var(--files); }
.card-score-A  { background: var(--score-a); }
.card-score-B  { background: var(--score-b); }
.card-score-C  { background: var(--score-c); color: #212121; }
.card-score-D  { background: var(--score-d); }
.card-score-E  { background: var(--score-e); }
.card-score-NA { background: var(--unknown); }

.verdict { padding: .6rem 2rem; font-size: .85rem; font-weight: 600; border-bottom: 1px solid #e0e0e0; }
.verdict.ok   { background: #e8f5e9; color: #1b5e20; }
.verdict.fail { background: #ffebee; color: #b71c1c; }

.messages { padding: .75rem 2rem; background: #fffbeb; border-bottom: 1px solid #fde68a; color: #92400e; font-size: .84rem; }
.messages b { display: block; margin-bottom: .3rem; }
.messages li { margin-left: 1.2rem; margin-top: .15rem; }

.filters { padding: .75rem 2rem; background: white; display: flex; gap: .5rem; border-bottom: 1px solid #e0e0e0; align-items: center; flex-wrap: wrap; }
.filters span { font-size: .85rem; color: #757575; margin-right: .25rem; }
.filters button {
  padding: .35rem .9rem; border: 2px solid #e0e0e0; border-radius: 20px;
  cursor: pointer; font-size: .82rem; font-weight: 600; background: white; color: #424242; transition: all .15s;
}
.filters button:hover { border-color: #9fa8da; }
.filters button.active { border-color: #1a237e; background: #e8eaf6; color: #1a237e; }
.filters select {
  padding: .35rem .75rem; border: 2px solid #e0e0e0; border-radius: 20px;
  font-size: .82rem; font-weight: 600; background: white; color: #424242; cursor: pointer; max-width: 360px;
}

.content { padding: 1.5rem 2rem; }

.target-group { background: white; border-radius: 8px; margin-bottom: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); overflow: hidden; }
.target-header {
  background: #37474f; color: white; padding: .85rem 1.25rem;
  display: flex; align-items: center; gap: .75rem; cursor: pointer; user-select: none;
}
.target-header:hover { background: #455a64; }
.target-toggle { font-size: .8rem; transition: transform .2s; display: inline-block; }
.target-group.collapsed .target-toggle { transform: rotate(-90deg); }
.target-group.collapsed table { display: none; }
.target-name { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .9rem; font-weight: 600; flex: 1; word-break: break-all; }
.target-type { font-size: .7rem; text-transform: uppercase; letter-spacing: .05em; padding: .2rem .55rem; border-radius: 4px; background: rgba(255,255,255,.15); }
.target-counts { display: flex; gap: .35rem; }
.target-counts .badge { font-size: .68rem; padding: .15rem .45rem; }

table { width: 100%; border-collapse: collapse; }
th { padding: .65rem 1rem; text-align: left; font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
     white-space: nowrap; background: #eceff1; color: #455a64; border-bottom: 1px solid #cfd8dc; }
td { padding: .7rem 1rem; font-size: .88rem; border-bottom: 1px solid #f5f5f5; vertical-align: top; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #fafafa; }
tr.row-hidden { display: none; }

.badge { display: inline-block; padding: .2rem .55rem; border-radius: 4px; font-size: .72rem; font-weight: 700; color: white; white-space: nowrap; }
.badge-CRITICAL { background: var(--critical); }
.badge-HIGH     { background: var(--high); }
.badge-MEDIUM   { background: var(--medium); color: #212121; }
.badge-LOW      { background: var(--low); }
.badge-INFO     { background: var(--info); }
.badge-UNKNOWN  { background: var(--unknown); }

.location  { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .8rem; color: #455a64; word-break: break-all; max-width: 200px; }
.rule-name { font-weight: 600; font-size: .86rem; max-width: 280px; }
.rule-code { display: block; font-family: 'SFMono-Regular', Consolas, monospace; font-size: .74rem; color: #757575; font-weight: 400; margin-top: .15rem; }
.desc      { max-width: 380px; font-size: .84rem; color: #424242; white-space: pre-line; }
.fix       { max-width: 320px; font-size: .82rem; color: #37474f; }
.links a   { display: block; font-size: .78rem; color: #1565c0; white-space: nowrap; }

.empty { text-align: center; padding: 3rem; color: #9e9e9e; font-size: .95rem; background: white; border-radius: 8px; }
.empty.warn { color: #92400e; background: #fffbeb; font-weight: 600; }
.target-group.all-hidden { display: none; }

.foot { padding: 1rem 2rem 2rem; font-size: .8rem; color: #616161; line-height: 1.7; }
.foot code { background: #e0e0e0; padding: .1rem .35rem; border-radius: 3px; font-size: .78rem; }
"""

JS = """
const groups = Array.from(document.querySelectorAll('.target-group'));
const rows = Array.from(document.querySelectorAll('tr[data-severity]'));
const targetSelect = document.getElementById('target-filter');

groups.forEach(g => {
  const opt = document.createElement('option');
  opt.value = g.dataset.target;
  opt.textContent = g.dataset.target;
  targetSelect.appendChild(opt);
});

let currentSeverity = 'ALL';
let currentTarget = 'ALL';

function applyFilters() {
  rows.forEach(r => {
    const sevMatch = currentSeverity === 'ALL' || r.dataset.severity === currentSeverity;
    const tgtMatch = currentTarget === 'ALL' || r.dataset.target === currentTarget;
    r.classList.toggle('row-hidden', !(sevMatch && tgtMatch));
  });
  groups.forEach(g => {
    const visible = g.querySelectorAll('tr[data-severity]:not(.row-hidden)').length;
    g.classList.toggle('all-hidden', visible === 0);
  });
}

function setFilter(severity) {
  currentSeverity = severity;
  document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
  document.getElementById('btn-' + severity).classList.add('active');
  applyFilters();
}

function setTargetFilter(target) {
  currentTarget = target;
  applyFilters();
}
"""

FOOTER = """
<div class="foot">
  <b>Accept a finding / silence a control</b> (applies to the whole control, Plumber has no per-line ignore):
  <code>enabled: false</code> under the control in <code>.plumber.yaml</code> &middot;
  or <code>PLUMBER_SKIP_CONTROLS: "controlA,controlB"</code> in the project's CI variables
  &mdash; leave a comment with the reason so the exception can be reviewed later.
  Many controls also accept allowlists (<code>trustedUrls</code>, <code>allowedPatterns</code>, ...):
  prefer them to disabling a whole control.
</div>
"""


def esc(value):
    return html.escape(str(value), quote=True) if value is not None else ""


def load_json(path):
    """Dict du fichier, ou None si absent / vide / illisible."""
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"erreur de lecture JSON ({path}): {e}", file=sys.stderr)
        return None
    return data if isinstance(data, dict) else None


def safe_url(url):
    """Uniquement http(s) : pas de lien javascript: dans le HTML."""
    if isinstance(url, str) and url.startswith(("https://", "http://")):
        return url
    return None


def norm_severity(value):
    sev = str(value or "UNKNOWN").upper()
    return sev if sev in SEV_RANK else "UNKNOWN"


def identifier(vuln, id_type):
    for item in vuln.get("identifiers") or []:
        if item.get("type") == id_type:
            return item
    return None


def collect(report):
    """Liste plate de findings normalises."""
    findings = []
    for v in report.get("vulnerabilities") or []:
        loc = v.get("location") or {}
        code_id = identifier(v, "plumber") or {}
        control_id = identifier(v, "plumber_control") or {}
        source = None
        for link in v.get("links") or []:
            source = safe_url(link.get("url"))
            if source:
                break
        findings.append({
            "file": loc.get("file") or "",
            "line": loc.get("start_line"),
            "control": control_id.get("value") or NO_CONTROL,
            "code": code_id.get("value") or "",
            "name": v.get("name") or v.get("message") or "Unnamed finding",
            "severity": norm_severity(v.get("severity")),
            # le message est le constat precis ; la description, le texte generique du code
            "detail": v.get("message") or v.get("description") or "",
            "fix": v.get("solution") or "",
            "doc": safe_url(code_id.get("url")),
            "source": source,
        })
    return findings


def group_by_control(findings):
    groups = {}
    for f in findings:
        groups.setdefault(f["control"], []).append(f)
    for items in groups.values():
        items.sort(key=lambda f: (SEV_RANK[f["severity"]], f["file"], f["line"] or 0))
    # controles les plus graves d'abord
    return sorted(groups.items(),
                  key=lambda kv: (SEV_RANK[kv[1][0]["severity"]], -len(kv[1]), kv[0]))


def collect_messages(report, summary):
    """Avertissements du scan (collecte degradee, config, ...), dedoublonnes."""
    msgs = []
    if report:
        for m in (report.get("scan") or {}).get("messages") or []:
            if m.get("value"):
                msgs.append(m["value"])
    if summary:
        msgs += [f"data collection incomplete: {r}" for r in summary.get("degradedReasons") or []]
        msgs += list(summary.get("warnings") or [])
        msgs += list(summary.get("ciErrors") or [])
    seen, out = set(), []
    for m in msgs:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def render_row(f, target):
    if f["file"]:
        location = f["file"] + (f":{f['line']}" if f["line"] else "")
    else:
        location = "project settings"
    links = ""
    if f["doc"]:
        links += f'<a href="{esc(f["doc"])}" target="_blank" rel="noopener">Docs</a>'
    if f["source"]:
        links += f'<a href="{esc(f["source"])}" target="_blank" rel="noopener">Source</a>'
    code = f'<span class="rule-code">{esc(f["code"])}</span>' if f["code"] else ""
    return (
        f'<tr data-severity="{f["severity"]}" data-target="{esc(target)}">'
        f'<td class="location">{esc(location)}</td>'
        f'<td class="rule-name">{esc(f["name"])}{code}</td>'
        f'<td><span class="badge badge-{f["severity"]}">{f["severity"]}</span></td>'
        f'<td class="desc">{esc(f["detail"])}</td>'
        f'<td class="fix">{esc(f["fix"])}</td>'
        f'<td class="links">{links}</td>'
        f'</tr>'
    )


def render_group(target, items):
    counts = {}
    for f in items:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    letters = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M", "LOW": "L", "INFO": "I", "UNKNOWN": "?"}
    badges = "".join(f'<span class="badge badge-{s}">{counts[s]} {letters[s]}</span>'
                     for s in SEVERITIES if s in counts)
    rows = "".join(render_row(f, target) for f in items)
    return f"""
<div class="target-group" data-target="{esc(target)}">
  <div class="target-header" onclick="this.parentElement.classList.toggle('collapsed')">
    <span class="target-toggle">&#9660;</span>
    <span class="target-name">{esc(target)}</span>
    <span class="target-type">CI/CD</span>
    <span class="target-counts">{badges}</span>
  </div>
  <table>
    <thead><tr><th>Location</th><th>Issue</th><th>Severity</th><th>Finding</th><th>Fix</th><th>References</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""


def render_score_card(summary):
    score = (summary or {}).get("plumberScore") or {}
    letter = str(score.get("score") or score.get("letter") or "").upper()
    points = score.get("finalPoints", score.get("points"))
    if letter not in ("A", "B", "C", "D", "E"):
        return ('<div class="card card-score-NA"><div class="count">&ndash;</div>'
                '<div class="label">Plumber score</div><div class="sub">withheld</div></div>')
    sub = f"{points:g} / 100" if isinstance(points, (int, float)) else ""
    return (f'<div class="card card-score-{letter}"><div class="count">{letter}</div>'
            f'<div class="label">Plumber score</div><div class="sub">{esc(sub)}</div></div>')


def render_verdict(summary):
    if not summary or "passed" not in summary:
        return ""
    if summary.get("passed"):
        return '<div class="verdict ok">Gate: PASSED</div>'
    return '<div class="verdict fail">Gate: FAILED</div>'


def render_html(report, summary):
    counts = {s: 0 for s in SEVERITIES}
    n_controls = 0
    project = (summary or {}).get("projectPath") or ""
    branch = (summary or {}).get("analyzeBranch") or ""

    if report is None:
        content = ('<div class="empty warn">Plumber report not found or unreadable. '
                   "The scan probably failed before producing results, check the job log. "
                   "This is NOT a clean result.</div>")
        scanner = "Plumber"
    elif summary and summary.get("ciMissing"):
        content = ('<div class="empty warn">No CI configuration was found for this project, '
                   "so no pipeline control could be evaluated. "
                   "This is NOT a clean result.</div>")
        sc = (report.get("scan") or {}).get("scanner") or {}
        scanner = f"{sc.get('name', 'Plumber')} {sc.get('version', '')}".strip()
    else:
        findings = collect(report)
        for f in findings:
            counts[f["severity"]] += 1
        groups = group_by_control(findings)
        n_controls = len(groups)
        content = ("".join(render_group(t, items) for t, items in groups)
                   or '<div class="empty">No issues found</div>')
        sc = (report.get("scan") or {}).get("scanner") or {}
        scanner = f"{sc.get('name', 'Plumber')} {sc.get('version', '')}".strip()

    messages = collect_messages(report, summary)
    messages_html = ""
    if messages:
        items = "".join(f"<li>{esc(m)}</li>" for m in messages)
        messages_html = (f'<div class="messages"><b>Warnings: some checks may be incomplete</b>'
                         f'<ul>{items}</ul></div>')

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    subtitle = " &mdash; ".join(x for x in (esc(project) + (f" ({esc(branch)})" if branch else ""),
                                            esc(scanner), f"generated on {now}") if x)
    cards = render_score_card(summary) + "".join(
        f'<div class="card card-{s.lower()}"><div class="count">{counts[s]}</div>'
        f'<div class="label">{s.capitalize()}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    ) + f'<div class="card card-files"><div class="count">{n_controls}</div><div class="label">Failing controls</div></div>'
    buttons = '<button class="active" id="btn-ALL" onclick="setFilter(\'ALL\')">All</button>' + "".join(
        f'<button id="btn-{s}" onclick="setFilter(\'{s}\')">{s.capitalize()}</button>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CI/CD Compliance Report (Plumber)</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>CI/CD Compliance Report</h1>
  <p>{subtitle}</p>
</header>
<div class="summary">{cards}</div>
{render_verdict(summary)}
{messages_html}
<div class="filters">
  <span>Severity:</span>
  {buttons}
  <span style="margin-left:1.5rem;">Control:</span>
  <select id="target-filter" onchange="setTargetFilter(this.value)">
    <option value="ALL">All controls</option>
  </select>
</div>
<div class="content">{content}</div>
{FOOTER}
<script>{JS}</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description="Rapport HTML a partir des rapports Plumber (glsast + JSON).")
    ap.add_argument("report", nargs="?", default=DEFAULT_REPORT,
                    help=f"rapport GitLab SAST produit par --glsast (defaut: {DEFAULT_REPORT})")
    ap.add_argument("-j", "--json", default=DEFAULT_JSON,
                    help=f"rapport JSON produit par --output, optionnel (defaut: {DEFAULT_JSON})")
    ap.add_argument("-o", "--out", default=DEFAULT_OUT,
                    help=f"fichier HTML de sortie (defaut: {DEFAULT_OUT})")
    args = ap.parse_args()

    report = load_json(args.report)
    summary = load_json(args.json)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render_html(report, summary))

    if report is None:
        print(f"attention: rapport introuvable/illisible ({args.report}), page d'avertissement ecrite", file=sys.stderr)
    else:
        n = len(report.get("vulnerabilities") or [])
        print(f"rapport genere: {args.out} ({n} findings)", file=sys.stderr)


if __name__ == "__main__":
    main()
