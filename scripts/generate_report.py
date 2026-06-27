#!/usr/bin/env python3
"""Consolide les sorties Prowler (OCSF), Checkov et tfsec en un rapport unique.

Produit trois artefacts dans le répertoire de sortie :
  - findings.json   : findings normalisés (schéma stable, triés par sévérité)
  - report.html     : rapport autoportant (CSS/JS inline, tableau triable)
  - remediation.md  : grille de remédiation priorisée

Aucune dépendance externe, aucun appel réseau : uniquement la bibliothèque standard.
"""
from __future__ import annotations

import argparse
import glob
import html
import json
import os
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {
    "critical": "Critique",
    "high": "Élevée",
    "medium": "Moyenne",
    "low": "Faible",
    "info": "Info",
}


# OCSF severity_id (0..6) — utilisé par Prowler quand le libellé texte est absent.
SEVERITY_ID_MAP = {0: "info", 1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical"}


def norm_severity(value) -> str:
    if value is None or value == "":
        return "medium"
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        return SEVERITY_ID_MAP.get(int(value), "medium")
    v = str(value).strip().lower()
    aliases = {
        "informational": "info",
        "moderate": "medium",
        "warning": "low",
        "error": "high",
        "fatal": "critical",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return aliases.get(v, "medium")


def load_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# --- Parsers par outil --------------------------------------------------------
def parse_checkov(data) -> list[dict]:
    """Checkov -o json : objet unique ou liste d'objets (multi-framework)."""
    findings = []
    blocks = data if isinstance(data, list) else [data]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = block.get("results", {})
        for chk in results.get("failed_checks", []):
            line = (chk.get("file_line_range") or [None])[0]
            findings.append(
                {
                    "source": "checkov",
                    "severity": norm_severity(chk.get("severity")),
                    "control": chk.get("check_id", ""),
                    "title": chk.get("check_name", ""),
                    "resource": chk.get("resource", ""),
                    "location": f"{chk.get('file_path', '')}:{line}" if line else chk.get("file_path", ""),
                    "status": "fail",
                    "remediation": chk.get("guideline") or "Voir la documentation Checkov du check.",
                }
            )
    return findings


def parse_tfsec(data) -> list[dict]:
    findings = []
    for res in (data or {}).get("results", []) or []:
        loc = res.get("location", {}) or {}
        findings.append(
            {
                "source": "tfsec",
                "severity": norm_severity(res.get("severity")),
                "control": res.get("long_id") or res.get("rule_id", ""),
                "title": res.get("rule_description", ""),
                "resource": res.get("resource", ""),
                "location": f"{loc.get('filename', '')}:{loc.get('start_line', '')}".rstrip(":"),
                "status": "fail",
                "remediation": res.get("resolution") or "; ".join(res.get("links", []) or []),
            }
        )
    return findings


def parse_prowler_ocsf(data) -> list[dict]:
    """Prowler --output-formats json-ocsf : liste de findings OCSF.

    Tolérant aux variations de schéma entre versions de Prowler : l'identifiant de
    check, la sévérité et la ressource sont cherchés à plusieurs emplacements connus.
    """
    findings = []
    for item in data or []:
        if not isinstance(item, dict):
            continue
        # Statut : ne garder que les échecs. status_code (FAIL/PASS) prioritaire ;
        # status (New/Suppressed) ne doit pas être confondu avec le résultat.
        status = str(item.get("status_code") or item.get("status") or "").upper()
        if status not in ("FAIL", "FAILED"):
            continue

        info = item.get("finding_info", {}) or {}
        meta = item.get("metadata", {}) or {}
        rem = item.get("remediation", {}) or {}
        unmapped = item.get("unmapped", {}) or {}
        resources = item.get("resources", []) or []
        res0 = resources[0] if resources else {}

        # Identifiant de contrôle : event_code (OCSF récent) -> unmapped -> uid.
        control = (
            meta.get("event_code")
            or unmapped.get("check_id")
            or info.get("uid")
            or (info.get("title", "")[:40])
        )
        # Sévérité : libellé texte sinon severity_id numérique.
        severity = item.get("severity")
        if severity in (None, "") and "severity_id" in item:
            severity = item.get("severity_id")

        title = info.get("title") or item.get("risk_details") or control
        resource = res0.get("name") or res0.get("uid") or ""
        region = res0.get("region") or (item.get("cloud", {}) or {}).get("region") or "aws"
        remediation = rem.get("desc") or "; ".join(rem.get("references", []) or []) \
            or "Voir la recommandation Prowler/CIS."

        findings.append(
            {
                "source": "prowler",
                "severity": norm_severity(severity),
                "control": control,
                "title": title,
                "resource": resource,
                "location": region,
                "status": "fail",
                "remediation": remediation,
            }
        )
    return findings


PARSERS = {"checkov": parse_checkov, "tfsec": parse_tfsec, "prowler": parse_prowler_ocsf}


def collect(report_dir: str, explicit: dict) -> list[dict]:
    findings: list[dict] = []
    # Fichiers passés explicitement.
    for tool, paths in explicit.items():
        for path in paths:
            data = load_json(path)
            if data is not None:
                findings += PARSERS[tool](data)
    # Auto-découverte dans le répertoire si rien d'explicite.
    if not any(explicit.values()):
        patterns = {
            "checkov": "checkov-*.json",
            "tfsec": "tfsec-*.json",
            "prowler": "*.ocsf.json",
        }
        for tool, pat in patterns.items():
            for path in sorted(glob.glob(os.path.join(report_dir, pat))):
                data = load_json(path)
                if data is not None:
                    findings += PARSERS[tool](data)
    return findings


def dedup(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in findings:
        key = (f["source"], f["control"], f["resource"], f["location"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["source"], f["control"]))
    return out


def summarize(findings: list[dict]) -> dict:
    by_sev = {k: 0 for k in SEVERITY_ORDER}
    by_src: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_src[f["source"]] = by_src.get(f["source"], 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_source": by_src}


# --- Rendu --------------------------------------------------------------------
def render_html(findings: list[dict], summary: dict, generated: str, synthetic: bool = False) -> str:
    rows = []
    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        rows.append(
            "<tr data-sev='{order}'>"
            "<td>{i}</td>"
            "<td><span class='sev sev-{sev}'>{sevlabel}</span></td>"
            "<td>{src}</td><td class='mono'>{ctrl}</td>"
            "<td>{title}</td><td class='mono'>{res}</td>"
            "<td class='mono'>{loc}</td><td>{rem}</td>"
            "</tr>".format(
                order=SEVERITY_ORDER.get(sev, 9),
                i=i,
                sev=sev,
                sevlabel=SEVERITY_LABEL[sev],
                src=html.escape(f["source"]),
                ctrl=html.escape(f["control"]),
                title=html.escape(f["title"]),
                res=html.escape(f["resource"]),
                loc=html.escape(f["location"]),
                rem=html.escape(f["remediation"]),
            )
        )
    cards = "".join(
        "<div class='card sev-{s}'><div class='n'>{n}</div><div class='l'>{lbl}</div></div>".format(
            s=s, n=summary["by_severity"].get(s, 0), lbl=SEVERITY_LABEL[s]
        )
        for s in SEVERITY_ORDER
    )
    sources = ", ".join(f"{k} ({v})" for k, v in sorted(summary["by_source"].items())) or "—"
    banner = (
        "<div class='syn'>⚠ Données illustratives (synthétiques) — généré depuis des fixtures, "
        "ne reflète aucun compte AWS réel.</div>"
        if synthetic
        else ""
    )
    return TEMPLATE.format(
        generated=html.escape(generated),
        total=summary["total"],
        sources=html.escape(sources),
        cards=cards,
        banner=banner,
        rows="\n".join(rows) or "<tr><td colspan='8'>Aucun finding.</td></tr>",
    )


def render_remediation(findings: list[dict], summary: dict, generated: str, synthetic: bool = False) -> str:
    lines = [
        "# Grille de remédiation priorisée",
        "",
    ]
    if synthetic:
        lines += [
            "> ⚠️ **Données illustratives (synthétiques)** — générées depuis des fixtures de démonstration.",
            "> Ne reflète aucun compte AWS réel.",
            "",
        ]
    lines += [
        f"_Généré le {generated}. Total : {summary['total']} findings._",
        "",
        "| # | Sévérité | Source | Contrôle | Ressource | Impact / constat | Correctif |",
        "|---|----------|--------|----------|-----------|------------------|-----------|",
    ]
    for i, f in enumerate(findings, 1):
        rem = f["remediation"].replace("|", "\\|").replace("\n", " ")
        title = f["title"].replace("|", "\\|")
        lines.append(
            f"| {i} | {SEVERITY_LABEL[f['severity']]} | {f['source']} | `{f['control']}` | "
            f"`{f['resource']}` | {title} | {rem} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Consolide Prowler/Checkov/tfsec en un rapport.")
    ap.add_argument("-d", "--report-dir", default="reports", help="Répertoire des entrées/sorties.")
    ap.add_argument("-o", "--output-dir", default=None, help="Répertoire de sortie (défaut: report-dir).")
    ap.add_argument("--checkov", action="append", default=[], help="Fichier JSON Checkov explicite.")
    ap.add_argument("--tfsec", action="append", default=[], help="Fichier JSON tfsec explicite.")
    ap.add_argument("--prowler", action="append", default=[], help="Fichier JSON OCSF Prowler explicite.")
    ap.add_argument("--synthetic", action="store_true",
                    help="Marque le rapport comme illustratif (fixtures, hors compte réel).")
    args = ap.parse_args()

    out_dir = args.output_dir or args.report_dir
    os.makedirs(out_dir, exist_ok=True)

    findings = dedup(
        collect(args.report_dir, {"checkov": args.checkov, "tfsec": args.tfsec, "prowler": args.prowler})
    )
    summary = summarize(findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump({"generated": generated, "synthetic": args.synthetic,
                   "summary": summary, "findings": findings}, fh,
                  indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(findings, summary, generated, args.synthetic))
    with open(os.path.join(out_dir, "remediation.md"), "w", encoding="utf-8") as fh:
        fh.write(render_remediation(findings, summary, generated, args.synthetic))

    print(f"{summary['total']} findings -> {out_dir}/findings.json, report.html, remediation.md")
    return 0


TEMPLATE = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport d'audit de sécurité AWS</title>
<style>
  :root {{ --bg:#0f1117; --panel:#171a22; --line:#262b36; --txt:#e6e8ee; --mut:#9aa3b2; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--txt); }}
  header {{ padding:28px 32px; border-bottom:1px solid var(--line); }}
  h1 {{ margin:0 0 4px; font-size:20px; }}
  .meta {{ color:var(--mut); font-size:13px; }}
  .cards {{ display:flex; gap:12px; padding:24px 32px; flex-wrap:wrap; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 18px; min-width:96px; }}
  .card .n {{ font-size:26px; font-weight:700; }}
  .card .l {{ color:var(--mut); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  .card.sev-critical {{ border-left:3px solid #e5484d; }}
  .card.sev-high {{ border-left:3px solid #f5a524; }}
  .card.sev-medium {{ border-left:3px solid #e0c000; }}
  .card.sev-low {{ border-left:3px solid #3b9eff; }}
  .card.sev-info {{ border-left:3px solid #6b7280; }}
  .wrap {{ padding:0 32px 48px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
  th, td {{ text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ background:#11141b; cursor:pointer; user-select:none; font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--mut); }}
  tr:last-child td {{ border-bottom:none; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:#c8d0dc; }}
  .sev {{ display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px; font-weight:600; }}
  .sev-critical {{ background:#3a1416; color:#ff7a7d; }}
  .sev-high {{ background:#3a2a10; color:#ffbf5c; }}
  .sev-medium {{ background:#34320c; color:#ede35a; }}
  .sev-low {{ background:#0f2740; color:#7cc0ff; }}
  .sev-info {{ background:#23262d; color:#aab2c0; }}
  td .sev {{ white-space:nowrap; }}
  .syn {{ background:#3a2a10; color:#ffce7a; border-bottom:1px solid #5a3f15; padding:10px 32px; font-size:13px; }}
</style>
</head>
<body>
{banner}
<header>
  <h1>Rapport d'audit de sécurité AWS</h1>
  <div class="meta">Généré le {generated} &middot; {total} findings &middot; Sources : {sources}</div>
</header>
<div class="cards">{cards}</div>
<div class="wrap">
  <table id="t">
    <thead><tr>
      <th onclick="sortBy(0)">#</th><th onclick="sortBy(1)">Sévérité</th>
      <th onclick="sortBy(2)">Source</th><th onclick="sortBy(3)">Contrôle</th>
      <th onclick="sortBy(4)">Constat</th><th onclick="sortBy(5)">Ressource</th>
      <th onclick="sortBy(6)">Emplacement</th><th onclick="sortBy(7)">Remédiation</th>
    </tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
</div>
<script>
  function sortBy(col) {{
    var tb = document.querySelector('#t tbody');
    var rows = Array.prototype.slice.call(tb.rows);
    var asc = tb.getAttribute('data-col') != col || tb.getAttribute('data-asc') != '1';
    rows.sort(function(a, b) {{
      var x = col === 1 ? +a.dataset.sev : a.cells[col].innerText.toLowerCase();
      var y = col === 1 ? +b.dataset.sev : b.cells[col].innerText.toLowerCase();
      return (x > y ? 1 : x < y ? -1 : 0) * (asc ? 1 : -1);
    }});
    rows.forEach(function(r) {{ tb.appendChild(r); }});
    tb.setAttribute('data-col', col); tb.setAttribute('data-asc', asc ? '1' : '0');
  }}
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
