#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convierte el cve-summary.json de Yocto a un HTML legible.
Uso:
  python cve-json-to-html.py /ruta/a/cve-summary.json --out cve-report.html
Opciones:
  --min-score 7.0     # opcional: filtra Unpatched con CVSSv3/2 >= 7.0
  --limit 200         # opcional: limita filas por tabla
"""

import argparse, json, html
from pathlib import Path
from typing import Any, Dict, List, Optional

def parse_score(v: Any) -> Optional[float]:
    try:
        if v is None or v == "" or str(v) == "0.0":
            return None
        return float(v)
    except Exception:
        return None

def load_rows(j: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for pkg in j.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        for issue in pkg.get("issue", []):
            rows.append({
                "package": name,
                "version": version,
                "cve_id": issue.get("id"),
                "status": (issue.get("status") or "").strip(),
                "scorev3": parse_score(issue.get("scorev3")),
                "scorev2": parse_score(issue.get("scorev2")),
                "summary": issue.get("summary") or "",
                "link": issue.get("link") or "",
            })
    return rows

def sort_key(row: Dict[str, Any]) -> float:
    # Ordena por CVSSv3 desc; si no hay, usa v2; si tampoco, -1
    s = row.get("scorev3")
    if s is None:
        s = row.get("scorev2")
    return s if s is not None else -1.0

def make_link(url: str) -> str:
    if not url:
        return ""
    # Texto corto para el anchor
    display = url.split("/")[-1] if len(url) > 60 else url
    return f'<a href="{html.escape(url)}" target="_blank" rel="noopener">{html.escape(display)}</a>'

def table_html(title: str, rows: List[Dict[str, Any]], limit: int) -> str:
    head = """
    <table>
      <thead>
        <tr>
          <th>Package</th><th>Version</th><th>CVE</th><th>Status</th><th>CVSS v3</th><th>CVSS v2</th><th>Link</th><th>Summary</th>
        </tr>
      </thead>
      <tbody>
    """
    body = []
    for r in rows[:limit]:
        body.append(
            "<tr>"
            f"<td>{html.escape(str(r.get('package') or ''))}</td>"
            f"<td>{html.escape(str(r.get('version') or ''))}</td>"
            f"<td>{html.escape(str(r.get('cve_id') or ''))}</td>"
            f"<td>{html.escape(str(r.get('status') or ''))}</td>"
            f"<td>{'' if r.get('scorev3') is None else f'{r['scorev3']:.1f}'}</td>"
            f"<td>{'' if r.get('scorev2') is None else f'{r['scorev2']:.1f}'}</td>"
            f"<td>{make_link(str(r.get('link') or ''))}</td>"
            f"<td>{html.escape(str(r.get('summary') or ''))}</td>"
            "</tr>"
        )
    tail = """
      </tbody>
    </table>
    """
    return f"<h2>{html.escape(title)}</h2>\n" + head + "\n".join(body) + tail

def build_html(all_rows: List[Dict[str, Any]], min_score: Optional[float], limit: int) -> str:
    # Split por estado
    unpatched = [r for r in all_rows if r["status"].lower() == "unpatched"]
    patched   = [r for r in all_rows if r["status"].lower() == "patched"]
    ignored   = [r for r in all_rows if r["status"].lower() not in ("unpatched", "patched")]

    # Filtrado por score si se pide (aplica solo a Unpatched)
    if min_score is not None:
        def score_ok(r):
            s = r.get("scorev3") if r.get("scorev3") is not None else r.get("scorev2")
            return (s is not None) and (s >= min_score)
        unpatched = [r for r in unpatched if score_ok(r)]

    # Ordenar por gravedad desc
    unpatched.sort(key=sort_key, reverse=True)
    patched.sort(key=sort_key, reverse=True)
    ignored.sort(key=sort_key, reverse=True)

    total = len(all_rows)
    html_head = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Yocto CVE Report</title>
<style>
 body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans', 'Liberation Sans', sans-serif; margin: 24px; }
 h1 { margin-top: 0; }
 table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
 th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
 th { background: #f5f5f5; text-align: left; }
 .pill { display:inline-block; padding: 2px 8px; border-radius: 999px; background:#eee; margin-left:8px; font-size:0.9em;}
 .ok { background: #e6f4ea; }
 .warn { background: #fff4e5; }
 .bad { background: #fdeaea; }
 .muted { color:#666; font-size: 0.95em; }
</style>
</head>
<body>
"""
    header = f"""
<h1>Yocto CVE Report</h1>
<p>
  <b>Total CVEs:</b> {total}
  <span class="pill bad"><b>Unpatched:</b> {len(unpatched)}</span>
  <span class="pill ok"><b>Patched:</b> {len(patched)}</span>
  <span class="pill warn"><b>Otros:</b> {len(ignored)}</span>
</p>
<p class="muted">Mostrando hasta {limit} filas por tabla.{" Filtro: CVSS ≥ " + str(min_score) if min_score is not None else ""}</p>
"""
    body = (
        table_html("Unpatched (ordenadas por severidad)", unpatched, limit) +
        table_html("Patched", patched, limit) +
        (table_html("Otros estados", ignored, limit) if ignored else "")
    )

    html_tail = """
</body>
</html>
"""
    return html_head + header + body + html_tail

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json_path", help="Ruta al cve-summary.json")
    ap.add_argument("--out", default="cve-report.html", help="Ruta de salida del HTML")
    ap.add_argument("--min-score", type=float, default=None, help="Filtra Unpatched por CVSS mínimo (v3 si hay, si no v2)")
    ap.add_argument("--limit", type=int, default=200, help="Límite de filas por tabla")
    args = ap.parse_args()

    src = Path(args.json_path)
    if not src.exists():
        raise SystemExit(f"No existe el fichero: {src}")

    with src.open("r", encoding="utf-8") as f:
        data = json.load(f)

    rows = load_rows(data)
    html_out = build_html(rows, args.min_score, args.limit)

    out_path = Path(args.out)
    out_path.write_text(html_out, encoding="utf-8")
    print(f"OK: generado {out_path} (filas totales: {len(rows)})")

if __name__ == "__main__":
    main()
