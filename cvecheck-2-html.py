#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convierte el cve-summary.json de Yocto a un HTML legible con:
- Ordenación por columna (click en encabezados)
- Columna "Attack Vector" (Network / Adjacent / Local / Physical) a partir del vector CVSS (v3 o v2)

Uso:
  python cve-json-to-html.py /ruta/a/cve-summary.json --out cve-report.html
Opciones:
  --min-score 7.0     # opcional: filtra Unpatched con CVSSv3/2 >= 7.0
  --limit 200         # opcional: limita filas por tabla
"""

import argparse, json, html
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------- Helpers de parsing ----------
def parse_score(v: Any) -> Optional[float]:
    try:
        if v is None or v == "" or str(v).strip() in {"0", "0.0"}:
            return None
        return float(v)
    except Exception:
        return None

def get_vectors(issue: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Devuelve (v3_vector, v2_vector) probando diferentes claves que
    pueden aparecer en cve-summary.json según versión/capa Yocto.
    """
    keys_v3 = [
        "cvss_v3_vector", "cvss3_vector", "cvssv3_vector",
        "vectorv3", "vector_v3", "vector3", "cvss_v3",
    ]
    keys_v2 = [
        "cvss_v2_vector", "cvss2_vector", "cvssv2_vector",
        "vectorv2", "vector_v2", "vector2", "cvss_v2",
    ]
    v3 = None
    v2 = None
    # Algunos reportes usan una sola clave "vector"
    raw = issue.get("vector") or issue.get("cvss_vector")
    if isinstance(raw, str) and raw:
        # Detecta si parece v3 (tiene "AV:" y, p.ej., "PR:" en v3) o v2
        if "PR:" in raw or "S:" in raw or "C:" in raw and "I:" in raw and "A:" in raw and ":" in raw:
            v3 = raw
        else:
            v2 = raw
    for k in keys_v3:
        if not v3:
            vv = issue.get(k)
            if isinstance(vv, str) and vv:
                v3 = vv
                break
    for k in keys_v2:
        if not v2:
            vv = issue.get(k)
            if isinstance(vv, str) and vv:
                v2 = vv
                break
    return v3, v2

def attack_vector_from_vectorstring(v: Optional[str]) -> Optional[str]:
    """
    Extrae el Attack Vector a partir del string CVSS (v2 o v3).
    Mapea:
      AV:N -> Network
      AV:A -> Adjacent
      AV:L -> Local
      AV:P -> Physical
    """
    if not isinstance(v, str):
        return None
    # Normaliza separadores en caso de distintos formatos
    s = v.replace(";", "/").upper()
    # Busca el token AV:?
    idx = s.find("AV:")
    if idx == -1:
        # algunos vectores v2 pueden venir como "AV:N/AC:M/Au:N/C:P/I:P/A:P"
        # ya cubierto por búsqueda; si no, intentamos dividir por '/'
        parts = s.split("/")
        for p in parts:
            p = p.strip()
            if p.startswith("AV:") and len(p) >= 4:
                code = p[3]
                break
        else:
            return None
    else:
        # lee el carácter siguiente al 'AV:'
        if len(s) >= idx + 4:
            code = s[idx + 3]
        else:
            return None

    return {
        "N": "Network",
        "A": "Adjacent",
        "L": "Local",
        "P": "Physical",
    }.get(code, None)

def load_rows(j: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for pkg in j.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        for issue in pkg.get("issue", []):
            v3_vec, v2_vec = get_vectors(issue)
            av = attack_vector_from_vectorstring(v3_vec or v2_vec)
            rows.append({
                "package": name,
                "version": version,
                "cve_id": issue.get("id"),
                "status": (issue.get("status") or "").strip(),
                "scorev3": parse_score(issue.get("scorev3")),
                "scorev2": parse_score(issue.get("scorev2")),
                "attack_vector": av or "",
                "vector_v3": v3_vec or "",
                "vector_v2": v2_vec or "",
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

# ---------- HTML + JS ----------
CSS = """
<style>
 body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans', 'Liberation Sans', sans-serif; margin: 24px; }
 h1 { margin-top: 0; }
 table { border-collapse: collapse; width: 100%; margin-bottom: 24px; }
 th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
 th { background: #f5f5f5; text-align: left; cursor: pointer; position: sticky; top: 0; }
 th .sort-indicator { font-size: 0.85em; opacity: 0.6; margin-left: 6px; }
 tr:nth-child(even) { background: #fafafa; }
 .pill { display:inline-block; padding: 2px 8px; border-radius: 999px; background:#eee; margin-left:8px; font-size:0.9em;}
 .ok { background: #e6f4ea; }
 .warn { background: #fff4e5; }
 .bad { background: #fdeaea; }
 .muted { color:#666; font-size: 0.95em; }
 .nowrap { white-space: nowrap; }
 .status-Unpatched { background: #fdeaea; }
 .status-Patched { background: #e6f4ea; }
 .status-Other { background: #fff4e5; }
</style>
"""

JS_SORT = """
<script>
// Tabla sortable sencilla (sin dependencias)
(function(){
  function getCellValue(row, idx) {
    const cell = row.children[idx];
    if (!cell) return '';
    const v = cell.getAttribute('data-sort') || cell.textContent || '';
    return v.trim();
  }
  function compareFactory(idx, type, asc) {
    return function(a, b) {
      const va = getCellValue(asc ? a : b, idx);
      const vb = getCellValue(asc ? b : a, idx);
      if (type === 'num') {
        const na = parseFloat(va); const nb = parseFloat(vb);
        const aa = isNaN(na) ? -Infinity : na;
        const bb = isNaN(nb) ? -Infinity : nb;
        return aa - bb;
      } else {
        return va.localeCompare(vb, undefined, {numeric:true, sensitivity:'base'});
      }
    };
  }
  function clearIndicators(ths) {
    ths.forEach(th => th.querySelector('.sort-indicator').textContent = '');
  }
  document.querySelectorAll('table.sortable').forEach(function(table){
    const ths = Array.from(table.querySelectorAll('thead th'));
    ths.forEach(function(th, idx){
      const indicator = document.createElement('span');
      indicator.className = 'sort-indicator';
      th.appendChild(indicator);
      let asc = true;
      th.addEventListener('click', function(){
        const type = th.getAttribute('data-type') || 'text';
        const tbody = table.tBodies[0];
        const rows = Array.from(tbody.querySelectorAll('tr')).filter(tr => tr.querySelectorAll('td').length);
        rows.sort(compareFactory(idx, type, asc));
        clearIndicators(ths);
        indicator.textContent = asc ? '▲' : '▼';
        asc = !asc;
        rows.forEach(r => tbody.appendChild(r));
      });
    });
  });
})();
</script>
"""

def make_link(url: str) -> str:
    if not url:
        return ""
    display = url.split("/")[-1] if len(url) > 60 else url
    return f'<a href="{html.escape(url)}" target="_blank" rel="noopener">{html.escape(display)}</a>'

def td(val: str, sort_val: Optional[str] = None, cls: str = "") -> str:
    attr_sort = f' data-sort="{html.escape(sort_val)}"' if sort_val is not None else ""
    attr_cls = f' class="{cls}"' if cls else ""
    return f"<td{attr_sort}{attr_cls}>{val}</td>"

def table_html(title: str, rows: List[Dict[str, Any]], limit: int) -> str:
    head = """
    <table class="sortable">
      <thead>
        <tr>
          <th data-type="text">Package</th>
          <th data-type="text">Version</th>
          <th data-type="text">CVE</th>
          <th data-type="text">Status</th>
          <th data-type="num">CVSS v3</th>
          <th data-type="num">CVSS v2</th>
          <th data-type="text">Attack Vector</th>
          <th data-type="text">Vector (v3/v2)</th>
          <th data-type="text">Link</th>
          <th data-type="text">Summary</th>
        </tr>
      </thead>
      <tbody>
    """
    body = []
    for r in rows[:limit]:
        status = r.get("status") or ""
        status_cls = "status-Other"
        if status.lower() == "unpatched":
            status_cls = "status-Unpatched"
        elif status.lower() == "patched":
            status_cls = "status-Patched"

        sv3 = r.get("scorev3")
        sv2 = r.get("scorev2")
        sv3_disp = "" if sv3 is None else f"{sv3:.1f}"
        sv2_disp = "" if sv2 is None else f"{sv2:.1f}"
        link_html = make_link(str(r.get("link") or ""))

        vector_combo = r.get("vector_v3") or r.get("vector_v2") or ""

        row_html = (
            "<tr>"
            + td(html.escape(str(r.get("package") or "")))
            + td(html.escape(str(r.get("version") or "")))
            + td(html.escape(str(r.get("cve_id") or "")))
            + td(html.escape(status), cls=status_cls)
            + td(html.escape(sv3_disp), sort_val=(str(sv3) if sv3 is not None else ""))
            + td(html.escape(sv2_disp), sort_val=(str(sv2) if sv2 is not None else ""))
            + td(html.escape(str(r.get("attack_vector") or "")))
            + td(html.escape(vector_combo))
            + td(link_html, sort_val=str(r.get("link") or ""))
            + td(html.escape(str(r.get("summary") or "")))
            + "</tr>"
        )
        body.append(row_html)
    tail = """
      </tbody>
    </table>
    """
    return f"<h2>{html.escape(title)}</h2>\n" + head + "\n".join(body) + tail

def build_html(all_rows: List[Dict[str, Any]], min_score: Optional[float], limit: int) -> str:
    # Split por estado
    unpatched = [r for r in all_rows if (r.get("status") or "").lower() == "unpatched"]
    patched   = [r for r in all_rows if (r.get("status") or "").lower() == "patched"]
    others    = [r for r in all_rows if (r.get("status") or "").lower() not in ("unpatched", "patched")]

    # Filtrado por score si se pide (solo Unpatched)
    if min_score is not None:
        def score_ok(r):
            s = r.get("scorev3") if r.get("scorev3") is not None else r.get("scorev2")
            return (s is not None) and (s >= min_score)
        unpatched = [r for r in unpatched if score_ok(r)]

    # Orden por gravedad para presentación inicial
    unpatched.sort(key=sort_key, reverse=True)
    patched.sort(key=sort_key, reverse=True)
    others.sort(key=sort_key, reverse=True)

    total = len(all_rows)
    html_head = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Yocto CVE Report</title>
{CSS}
</head>
<body>
"""
    header = f"""
<h1>Yocto CVE Report</h1>
<p>
  <b>Total CVEs:</b> {total}
  <span class="pill bad"><b>Unpatched:</b> {len(unpatched)}</span>
  <span class="pill ok"><b>Patched:</b> {len(patched)}</span>
  <span class="pill warn"><b>Otros:</b> {len(others)}</span>
</p>
<p class="muted">Clic en el encabezado para ordenar (alternando asc/desc). Mostrando hasta {limit} filas por tabla.{" Filtro: CVSS ≥ " + str(min_score) if min_score is not None else ""}</p>
"""
    body = (
        table_html("Unpatched (ordenadas por severidad)", unpatched, limit) +
        table_html("Patched", patched, limit) +
        (table_html("Otros estados", others, limit) if others else "")
    )

    html_tail = f"""
{JS_SORT}
</body>
</html>
"""
    return html_head + header + body + html_tail

# ---------- CLI ----------
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
