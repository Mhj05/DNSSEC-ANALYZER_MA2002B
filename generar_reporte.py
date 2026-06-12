#!/usr/bin/env python3
"""
Generador de reporte DNSSEC — MA2002B
Lee dnssec_results.json (salida de cripto_reto.py) y genera:
  - resultados_dnssec.xlsx  (varias hojas con los registros analizados)
  - reporte_dnssec.html     (reporte visual con árbol de cadena de confianza)

Uso:
    python generar_reporte.py dnssec_results.json
"""

import sys
import json
import html as html_lib
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx


# ─────────────────────────────────────────────────────────────────────────────
# Carga de datos
# ─────────────────────────────────────────────────────────────────────────────

def load_data(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# Construcción de DataFrames (para Excel/CSV)
# ─────────────────────────────────────────────────────────────────────────────

def build_dnskey_df(data: dict) -> pd.DataFrame:
    rows = []
    for domain, res in data["dnskey"].items():
        m = res["metrics"]
        if not m.get("found"):
            rows.append({"dominio": domain, "key_tag": None, "tipo": None,
                          "algoritmo": None, "estado_algoritmo": None,
                          "estado_clave": "SIN DNSKEY", "rfc_compliant": False,
                          "ttl": None})
            continue
        for r in res["records"]:
            rows.append({
                "dominio": domain,
                "key_tag": r["key_tag"],
                "tipo": r["type"],
                "algoritmo": r["alg_name"],
                "estado_algoritmo": r["alg_status"],
                "estado_clave": r["key_state"],
                "rfc_compliant": r["rfc_compliant"],
                "ttl": m.get("ttl"),
            })
    return pd.DataFrame(rows)


def build_rrsig_df(data: dict) -> pd.DataFrame:
    rows = []
    for domain, res in data["rrsig"].items():
        m = res["metrics"]
        if not m.get("found"):
            rows.append({"dominio": domain, "tipo_consultado": res.get("rdtype"),
                          "key_tag": None, "algoritmo": None, "firmante": None,
                          "inicio": None, "expiracion": None, "estado": "SIN RRSIG",
                          "ad_flag": m.get("ad_flag")})
            continue
        for r in res["records"]:
            rows.append({
                "dominio": domain,
                "tipo_consultado": res.get("rdtype"),
                "key_tag": r["key_tag"],
                "algoritmo": r["alg_name"],
                "firmante": r["signer"],
                "inicio": r["inception"],
                "expiracion": r["expiration"],
                "estado": r["state"],
                "ad_flag": m.get("ad_flag"),
            })
    return pd.DataFrame(rows)


def build_ds_df(data: dict) -> pd.DataFrame:
    rows = []
    for domain, res in data["ds"].items():
        m = res["metrics"]
        if not m.get("found"):
            rows.append({"dominio": domain, "key_tag": None, "algoritmo": None,
                          "digest": None, "cadena_valida": None,
                          "digest_deprecado": None, "cadena_integra_global": False,
                          "error": m.get("error")})
            continue
        for r in res["records"]:
            rows.append({
                "dominio": domain,
                "key_tag": r["key_tag"],
                "algoritmo": r["alg_name"],
                "digest": r["digest_name"],
                "cadena_valida": r["chain_valid"],
                "digest_deprecado": r["digest_deprecated"],
                "cadena_integra_global": m.get("trust_chain_ok"),
                "error": None,
            })
    return pd.DataFrame(rows)


def build_nsec_df(data: dict) -> pd.DataFrame:
    rows = []
    for domain, res in data["nsec"].items():
        m = res["metrics"]
        rows.append({
            "dominio": domain,
            "tipo": res.get("type"),
            "usa_nsec3": m.get("uses_nsec3"),
            "usa_nsec": m.get("uses_nsec"),
            "encontrado": m.get("found"),
            "ttl": m.get("ttl"),
        })
    return pd.DataFrame(rows)


def build_tree_df(data: dict) -> pd.DataFrame:
    edges = data["trust_tree"]["edges"]
    nodes = data["trust_tree"]["nodes"]
    rows = []
    for e in edges:
        child = nodes.get(e["child"], {})
        rows.append({
            "padre": e["parent"],
            "hijo": e["child"],
            "tiene_dnskey": child.get("has_dnskey"),
            "tiene_ds": child.get("has_ds"),
            "cadena_ds_valida": e["chain_ok"],
            "ksk": child.get("ksk_count"),
            "zsk": child.get("zsk_count"),
        })
    return pd.DataFrame(rows)


def build_charts_data(data: dict) -> dict:
    """Calcula distribuciones para las gráficas del dashboard."""
    total = data["global_metrics"]["total_domains"]

    # DS: con cadena íntegra / sin DS o cadena rota
    ds_ok = data["global_metrics"]["ds_chain_valid"]
    ds_total_with_parent = total - 1
    ds_chart = [
        {"label": "Cadena DS íntegra", "value": ds_ok},
        {"label": "Sin DS / cadena rota", "value": ds_total_with_parent - ds_ok},
    ]

    # DNSKEY: con / sin DNSKEY
    dnskey_ok = data["global_metrics"]["with_dnskey"]
    dnskey_chart = [
        {"label": "Con DNSKEY", "value": dnskey_ok},
        {"label": "Sin DNSKEY", "value": total - dnskey_ok},
    ]

    # RRSIG estados (agregando todos los registros)
    rrsig_states = {"VÁLIDA": 0, "EXPIRADA": 0, "NO VÁLIDA AÚN (futura)": 0, "SIN RRSIG": 0}
    for domain, res in data["rrsig"].items():
        m = res["metrics"]
        if not m.get("found"):
            rrsig_states["SIN RRSIG"] += 1
            continue
        for r in res["records"]:
            rrsig_states[r["state"]] = rrsig_states.get(r["state"], 0) + 1
    rrsig_chart = [{"label": k, "value": v} for k, v in rrsig_states.items() if v > 0]

    # NSEC tipo
    nsec_types = {}
    for domain, res in data["nsec"].items():
        t = res.get("type") or "NINGUNO"
        label = {
            "NSEC3PARAM+NSEC3": "NSEC3 (seguro)",
            "NSEC3": "NSEC3 (seguro)",
            "NSEC": "NSEC (enumerable)",
            "NINGUNO": "Sin NSEC/NSEC3",
        }.get(t, t)
        nsec_types[label] = nsec_types.get(label, 0) + 1
    nsec_chart = [{"label": k, "value": v} for k, v in nsec_types.items()]

    # Algoritmos DNSKEY: autorizados vs deprecados/prohibidos
    auth = data["global_metrics"]["alg_authorized"]
    dep  = data["global_metrics"]["alg_deprecated"]
    alg_chart = [
        {"label": "Autorizados (RFC 8624)", "value": auth},
        {"label": "Deprecados / prohibidos", "value": dep},
    ]

    # Distribución de algoritmos DNSKEY por nombre
    alg_names = {}
    for domain, res in data["dnskey"].items():
        if not res["metrics"].get("found"):
            continue
        for r in res["records"]:
            alg_names[r["alg_name"]] = alg_names.get(r["alg_name"], 0) + 1
    alg_name_chart = [{"label": k, "value": v} for k, v in
                       sorted(alg_names.items(), key=lambda x: -x[1])]

    return {
        "ds": ds_chart,
        "dnskey": dnskey_chart,
        "rrsig": rrsig_chart,
        "nsec": nsec_chart,
        "alg_status": alg_chart,
        "alg_names": alg_name_chart,
    }


def build_summary_df(data: dict) -> pd.DataFrame:
    gm = data["global_metrics"]
    rows = [
        {"métrica": "Dominios analizados", "valor": gm["total_domains"]},
        {"métrica": "Con DNSKEY", "valor": gm["with_dnskey"]},
        {"métrica": "Con RRSIG válido", "valor": gm["with_rrsig"]},
        {"métrica": "Con cadena DS íntegra", "valor": gm["ds_chain_valid"]},
        {"métrica": "Usan NSEC3", "valor": gm["use_nsec3"]},
        {"métrica": "Usan NSEC (enumeración)", "valor": gm["use_nsec_only"]},
        {"métrica": "Firmas RRSIG expiradas (dominios)", "valor": gm["rrsig_expired"]},
        {"métrica": "Algoritmos autorizados (RFC 8624)", "valor": gm["alg_authorized"]},
        {"métrica": "Algoritmos deprecados/prohibidos", "valor": gm["alg_deprecated"]},
    ]
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Excel
# ─────────────────────────────────────────────────────────────────────────────

def export_excel(data: dict, out_path: str):
    summary_df = build_summary_df(data)
    dnskey_df  = build_dnskey_df(data)
    rrsig_df   = build_rrsig_df(data)
    ds_df      = build_ds_df(data)
    nsec_df    = build_nsec_df(data)
    tree_df    = build_tree_df(data)

    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Resumen", index=False)
        dnskey_df.to_excel(writer, sheet_name="DNSKEY", index=False)
        rrsig_df.to_excel(writer, sheet_name="RRSIG", index=False)
        ds_df.to_excel(writer, sheet_name="DS", index=False)
        nsec_df.to_excel(writer, sheet_name="NSEC", index=False)
        tree_df.to_excel(writer, sheet_name="Cadena_Confianza", index=False)

    # Autoajustar ancho de columnas
    from openpyxl import load_workbook
    wb = load_workbook(out_path)
    for ws in wb.worksheets:
        for col in ws.columns:
            max_len = max((len(str(c.value)) if c.value is not None else 0) for c in col)
            ws.column_dimensions[col[0].column_letter].width = min(max(max_len + 2, 10), 50)
    wb.save(out_path)


# ─────────────────────────────────────────────────────────────────────────────
# HTML — Árbol de cadena de confianza (D3.js)
# ─────────────────────────────────────────────────────────────────────────────

def build_d3_tree_data(data: dict) -> dict:
    """Convierte nodes/edges en una estructura jerárquica para D3."""
    nodes = data["trust_tree"]["nodes"]
    edges = data["trust_tree"]["edges"]

    children_map = {}
    for e in edges:
        children_map.setdefault(e["parent"], []).append(e)

    def build(node_name):
        n = nodes.get(node_name, {})
        if node_name == ".":
            status = "root"
        else:
            has_dnskey = n.get("has_dnskey", False)
            has_ds     = n.get("has_ds", False)
            chain_ok   = n.get("trust_chain", False)
            if has_dnskey and has_ds and chain_ok:
                status = "ok"
            elif has_dnskey and not has_ds:
                status = "incomplete"
            elif has_dnskey:
                status = "warn"
            else:
                status = "none"

        node_obj = {
            "name": node_name,
            "status": status,
            "ksk": n.get("ksk_count", 0),
            "zsk": n.get("zsk_count", 0),
            "dnskey_ttl": n.get("dnskey_ttl"),
            "ds_ttl": n.get("ds_ttl"),
        }
        kids = []
        for e in sorted(children_map.get(node_name, []), key=lambda x: x["child"]):
            kids.append(build(e["child"]))
        if kids:
            node_obj["children"] = kids
        return node_obj

    return build(".")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Reporte DNSSEC — MA2002B</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
  :root {{
    --bg: #0f1420;
    --panel: #161d2e;
    --panel-border: #2a3650;
    --text: #e6eaf2;
    --muted: #8b97b3;
    --accent: #5b8def;
    --ok: #36b37e;
    --warn: #ffab00;
    --bad: #f25c54;
    --none: #5a6478;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: 'Segoe UI', system-ui, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
  }}
  header {{
    padding: 28px 32px;
    border-bottom: 1px solid var(--panel-border);
    background: linear-gradient(135deg, #1a2236, #0f1420);
  }}
  header h1 {{ margin: 0 0 4px 0; font-size: 24px; }}
  header p {{ margin: 0; color: var(--muted); font-size: 14px; }}

  main {{ padding: 24px 32px 60px; max-width: 1300px; margin: 0 auto; }}

  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 14px;
    margin: 24px 0 36px;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 10px;
    padding: 16px;
  }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .card .label {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}

  section {{ margin-bottom: 44px; }}
  h2 {{ font-size: 18px; border-left: 4px solid var(--accent); padding-left: 10px; }}
  .legend {{ display:flex; gap:18px; flex-wrap:wrap; font-size:13px; color:var(--muted); margin: 8px 0 18px;}}
  .legend span {{ display:inline-flex; align-items:center; gap:6px; }}
  .dot {{ width:12px; height:12px; border-radius:50%; display:inline-block; }}

  #tree {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 10px;
    overflow: auto;
  }}

  .charts-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
  }}
  .chart-card {{
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 10px;
    padding: 14px 16px;
  }}
  .chart-card h3 {{ margin: 0 0 8px 0; font-size: 14px; color: var(--text); font-weight: 600; }}
  .chart-legend {{ font-size: 12px; color: var(--muted); margin-top: 8px; }}
  .chart-legend div {{ display:flex; align-items:center; gap:6px; margin: 3px 0; }}
  .chart-legend i {{ width: 10px; height: 10px; border-radius: 2px; display:inline-block; flex-shrink:0; }}
  .chart-pct {{ margin-left: auto; font-weight: 600; color: var(--text); }}
  .bar-row {{ display:flex; align-items:center; gap:8px; font-size:12px; margin: 6px 0; }}
  .bar-label {{ width: 170px; flex-shrink:0; color: var(--muted); text-align:right; }}
  .bar-track {{ flex:1; background:#1d2640; border-radius:4px; height:14px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:4px; }}
  .bar-val {{ width: 36px; text-align:left; font-weight:600; }}
  .node circle {{ stroke-width: 2px; cursor: pointer; }}
  .node text {{ font-size: 12px; fill: var(--text); }}
  .link {{ fill: none; stroke: #3a4a6b; stroke-width: 1.5px; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; background: var(--panel);
           border: 1px solid var(--panel-border); border-radius: 10px; overflow: hidden;}}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid var(--panel-border); text-align: left; }}
  th {{ background: #1d2640; color: var(--muted); font-weight: 600; position: sticky; top:0; }}
  tr:hover td {{ background: #1c2438; }}
  .pill {{ padding: 2px 8px; border-radius: 99px; font-size: 11px; font-weight: 600; }}
  .pill-ok    {{ background: rgba(54,179,126,.15); color: var(--ok); }}
  .pill-warn  {{ background: rgba(255,171,0,.15); color: var(--warn); }}
  .pill-bad   {{ background: rgba(242,92,84,.15); color: var(--bad); }}
  .pill-none  {{ background: rgba(90,100,120,.2); color: var(--none); }}

  .table-wrap {{ max-height: 420px; overflow: auto; border-radius: 10px; }}
  footer {{ color: var(--muted); font-size: 12px; text-align:center; padding: 20px; }}
</style>
</head>
<body>

<header>
  <h1>Reporte de análisis DNSSEC</h1>
  <p>MA2002B — Análisis de Criptografía y Seguridad de Redes · Tecnológico de Monterrey</p>
  <p>Generado: {timestamp} &nbsp;|&nbsp; Resolver: {nameserver} &nbsp;|&nbsp; RFC 4033-4035, 5155, 6840, 8624</p>
</header>

<main>

<section>
  <h2>Resumen global</h2>
  <div class="cards">
    {cards_html}
  </div>
</section>

<section>
  <h2>Gráficas generales</h2>
  <div class="charts-grid">
    <div class="chart-card"><h3>Cadena DS íntegra</h3><div id="chart-ds"></div></div>
    <div class="chart-card"><h3>Dominios con DNSKEY</h3><div id="chart-dnskey"></div></div>
    <div class="chart-card"><h3>Estado de firmas RRSIG</h3><div id="chart-rrsig"></div></div>
    <div class="chart-card"><h3>NSEC / NSEC3</h3><div id="chart-nsec"></div></div>
    <div class="chart-card"><h3>Algoritmos: RFC 8624</h3><div id="chart-algstatus"></div></div>
    <div class="chart-card"><h3>Algoritmos DNSKEY usados</h3><div id="chart-algnames"></div></div>
  </div>
</section>

<section>
  <h2>Árbol de cadena de confianza</h2>
  <p style="color:var(--muted); font-size:13px; margin-top:-6px;">
    Desde la raíz (.) hasta cada dominio analizado. Verde = cadena DS→DNSKEY íntegra,
    amarillo = DNSKEY presente pero cadena no verificable o sin DS, gris = sin DNSSEC.
  </p>
  <div class="legend">
    <span><i class="dot" style="background:var(--accent)"></i> Raíz / ancla de confianza</span>
    <span><i class="dot" style="background:var(--ok)"></i> DNSSEC OK (cadena íntegra)</span>
    <span><i class="dot" style="background:var(--warn)"></i> Cadena incompleta / no verificable</span>
    <span><i class="dot" style="background:var(--none)"></i> Sin DNSSEC</span>
  </div>
  <div id="tree"></div>
</section>

<section>
  <h2>DNSKEY</h2>
  <div class="table-wrap">{dnskey_table}</div>
</section>

<section>
  <h2>RRSIG</h2>
  <div class="table-wrap">{rrsig_table}</div>
</section>

<section>
  <h2>DS — Cadena de confianza</h2>
  <div class="table-wrap">{ds_table}</div>
</section>

<section>
  <h2>NSEC / NSEC3 / NSEC3PARAM</h2>
  <div class="table-wrap">{nsec_table}</div>
</section>

</main>

<footer>Generado automáticamente a partir de dnssec_results.json — A00841920</footer>

<script>
const treeData = {tree_json};

const colors = {{
  root: "var(--accent)",
  ok: "var(--ok)",
  warn: "var(--warn)",
  incomplete: "var(--warn)",
  none: "var(--none)"
}};

const margin = {{top: 20, right: 160, bottom: 20, left: 80}};
const root = d3.hierarchy(treeData);
const nodeCount = root.descendants().length;
const width = Math.max(900, nodeCount * 14);
const height = Math.max(400, root.descendants().filter(d => !d.children).length * 26);

const treeLayout = d3.tree().size([height - margin.top - margin.bottom, width - margin.left - margin.right]);
treeLayout(root);

const svg = d3.select("#tree").append("svg")
  .attr("width", width)
  .attr("height", height)
  .append("g")
  .attr("transform", `translate(${{margin.left}},${{margin.top}})`);

svg.selectAll(".link")
  .data(root.links())
  .join("path")
  .attr("class", "link")
  .attr("d", d3.linkHorizontal()
    .x(d => d.y)
    .y(d => d.x));

const node = svg.selectAll(".node")
  .data(root.descendants())
  .join("g")
  .attr("class", "node")
  .attr("transform", d => `translate(${{d.y}},${{d.x}})`);

node.append("circle")
  .attr("r", 6)
  .attr("fill", d => colors[d.data.status] || "var(--none)")
  .attr("stroke", "#0f1420");

node.append("title")
  .text(d => {{
    const n = d.data;
    let parts = [n.name];
    if (n.ksk || n.zsk) parts.push(`KSK=${{n.ksk}} ZSK=${{n.zsk}}`);
    if (n.dnskey_ttl) parts.push(`TTL DNSKEY=${{n.dnskey_ttl}}s`);
    if (n.ds_ttl) parts.push(`TTL DS=${{n.ds_ttl}}s`);
    return parts.join(" | ");
  }});

node.append("text")
  .attr("dy", "0.32em")
  .attr("x", d => d.children ? -10 : 10)
  .attr("text-anchor", d => d.children ? "end" : "start")
  .text(d => d.data.name);

// ── Gráficas ─────────────────────────────────────────────────────────────
const chartsData = {charts_json};

const palette = ["#36b37e", "#f25c54", "#ffab00", "#5b8def", "#9b8cf2", "#5a6478", "#36c5d9"];

function drawDonut(containerId, items) {{
  const total = items.reduce((s, i) => s + i.value, 0) || 1;
  const size = 140, radius = size / 2;
  const arcGen = d3.arc().innerRadius(radius * 0.55).outerRadius(radius);
  const pieGen = d3.pie().value(d => d.value).sort(null);

  const container = d3.select("#" + containerId);
  const wrap = container.append("div").style("display", "flex")
    .style("align-items", "center").style("gap", "14px").style("flex-wrap", "wrap");

  const svg = wrap.append("svg").attr("width", size).attr("height", size)
    .append("g").attr("transform", `translate(${{radius}},${{radius}})`);

  svg.selectAll("path")
    .data(pieGen(items))
    .join("path")
    .attr("d", arcGen)
    .attr("fill", (d, i) => palette[i % palette.length])
    .attr("stroke", "var(--panel)")
    .attr("stroke-width", 2)
    .append("title")
    .text(d => `${{d.data.label}}: ${{d.data.value}}`);

  svg.append("text")
    .attr("text-anchor", "middle")
    .attr("dy", "0.35em")
    .style("fill", "var(--text)")
    .style("font-size", "18px")
    .style("font-weight", "700")
    .text(total);

  const legend = wrap.append("div").attr("class", "chart-legend");
  items.forEach((d, i) => {{
    const pct = ((d.value / total) * 100).toFixed(1);
    const row = legend.append("div");
    row.append("i").style("background", palette[i % palette.length]);
    row.append("span").text(`${{d.label}}: ${{d.value}}`);
    row.append("span").attr("class", "chart-pct").text(pct + "%");
  }});
}}

function drawBars(containerId, items) {{
  const max = Math.max(...items.map(d => d.value), 1);
  const container = d3.select("#" + containerId);
  items.forEach((d, i) => {{
    const row = container.append("div").attr("class", "bar-row");
    row.append("div").attr("class", "bar-label").text(d.label);
    const track = row.append("div").attr("class", "bar-track");
    track.append("div").attr("class", "bar-fill")
      .style("width", (d.value / max * 100) + "%")
      .style("background", palette[i % palette.length]);
    row.append("div").attr("class", "bar-val").text(d.value);
  }});
}}

if (chartsData.ds.some(d => d.value > 0))        drawDonut("chart-ds", chartsData.ds);
if (chartsData.dnskey.some(d => d.value > 0))    drawDonut("chart-dnskey", chartsData.dnskey);
if (chartsData.rrsig.some(d => d.value > 0))     drawDonut("chart-rrsig", chartsData.rrsig);
if (chartsData.nsec.some(d => d.value > 0))      drawDonut("chart-nsec", chartsData.nsec);
if (chartsData.alg_status.some(d => d.value > 0)) drawDonut("chart-algstatus", chartsData.alg_status);
if (chartsData.alg_names.length)                 drawBars("chart-algnames", chartsData.alg_names);
</script>

</body>
</html>
"""


def pill(value, kind_true="ok", kind_false="bad", text_true=None, text_false=None):
    if value is True:
        cls, txt = kind_true, (text_true or "Sí")
    elif value is False:
        cls, txt = kind_false, (text_false or "No")
    else:
        cls, txt = "none", "—"
    return f'<span class="pill pill-{cls}">{txt}</span>'


def df_to_html_table(df: pd.DataFrame, pill_cols=None) -> str:
    """pill_cols: {col_name: (kind_true, kind_false, text_true, text_false)}"""
    pill_cols = pill_cols or {}
    headers = "".join(f"<th>{html_lib.escape(str(c))}</th>" for c in df.columns)
    rows_html = []
    for _, row in df.iterrows():
        cells = []
        for c in df.columns:
            v = row[c]
            if c in pill_cols and isinstance(v, bool):
                args = pill_cols[c]
                kt = args[0] if len(args) > 0 else "ok"
                kf = args[1] if len(args) > 1 else "bad"
                tt = args[2] if len(args) > 2 else None
                tf = args[3] if len(args) > 3 else None
                cells.append(f"<td>{pill(v, kt, kf, tt, tf)}</td>")
            elif pd.isna(v):
                cells.append("<td>—</td>")
            else:
                cells.append(f"<td>{html_lib.escape(str(v))}</td>")
        rows_html.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{headers}</tr></thead><tbody>{''.join(rows_html)}</tbody></table>"


def export_html(data: dict, out_path: str):
    gm = data["global_metrics"]
    total = gm["total_domains"]

    cards = [
        ("Dominios analizados", gm["total_domains"]),
        ("Con DNSKEY", f'{gm["with_dnskey"]}/{total}'),
        ("Con RRSIG válido", f'{gm["with_rrsig"]}/{total}'),
        ("Cadena DS íntegra", f'{gm["ds_chain_valid"]}/{total-1}'),
        ("Usan NSEC3", gm["use_nsec3"]),
        ("Usan NSEC (enumeración)", gm["use_nsec_only"]),
        ("RRSIG expiradas", gm["rrsig_expired"]),
        ("Algoritmos autorizados", gm["alg_authorized"]),
        ("Algoritmos deprecados", gm["alg_deprecated"]),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="num">{v}</div><div class="label">{k}</div></div>'
        for k, v in cards
    )

    dnskey_df = build_dnskey_df(data)
    rrsig_df  = build_rrsig_df(data)
    ds_df     = build_ds_df(data)
    nsec_df   = build_nsec_df(data)

    dnskey_table = df_to_html_table(dnskey_df, {"rfc_compliant": ("ok", "bad")})
    rrsig_table  = df_to_html_table(rrsig_df,  {"ad_flag": ("ok", "none")})
    ds_table     = df_to_html_table(ds_df, {
        "cadena_valida": ("ok", "bad"),
        "digest_deprecado": ("warn", "none", "Sí (SHA-1)", "No"),
        "cadena_integra_global": ("ok", "bad"),
    })
    nsec_table   = df_to_html_table(nsec_df, {
        "usa_nsec3": ("ok", "none"),
        "usa_nsec": ("warn", "none"),
        "encontrado": ("ok", "bad"),
    })

    tree_json = json.dumps(build_d3_tree_data(data), ensure_ascii=False)
    charts_json = json.dumps(build_charts_data(data), ensure_ascii=False)

    html_out = HTML_TEMPLATE.format(
        timestamp=html_lib.escape(data.get("timestamp", "")),
        nameserver=html_lib.escape(data.get("nameserver", "")),
        cards_html=cards_html,
        dnskey_table=dnskey_table,
        rrsig_table=rrsig_table,
        ds_table=ds_table,
        nsec_table=nsec_table,
        tree_json=tree_json,
        charts_json=charts_json,
    )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_out)


# ─────────────────────────────────────────────────────────────────────────────
# Gráficas estáticas (PNG) — matplotlib / networkx
# ─────────────────────────────────────────────────────────────────────────────

PALETTE = ["#36b37e", "#f25c54", "#ffab00", "#5b8def", "#9b8cf2", "#5a6478", "#36c5d9"]

plt.rcParams.update({
    "figure.facecolor": "#0f1420",
    "axes.facecolor": "#161d2e",
    "savefig.facecolor": "#0f1420",
    "text.color": "#e6eaf2",
    "axes.labelcolor": "#e6eaf2",
    "xtick.color": "#8b97b3",
    "ytick.color": "#8b97b3",
    "axes.edgecolor": "#2a3650",
    "font.size": 10,
})


def _donut(ax, items, title):
    items = [d for d in items if d["value"] > 0]
    if not items:
        ax.axis("off")
        ax.set_title(title, fontsize=11)
        return
    labels = [d["label"] for d in items]
    values = [d["value"] for d in items]
    colors = PALETTE[:len(items)]
    wedges, _texts, autotexts = ax.pie(
        values, colors=colors, autopct="%1.1f%%", startangle=90,
        pctdistance=0.78, wedgeprops={"width": 0.45, "edgecolor": "#0f1420"},
    )
    for at in autotexts:
        at.set_color("#0f1420")
        at.set_fontsize(8)
        at.set_fontweight("bold")
    ax.set_title(title, fontsize=11, pad=10)
    ax.legend(wedges, [f"{l} ({v})" for l, v in zip(labels, values)],
              loc="center left", bbox_to_anchor=(1.0, 0.5), fontsize=8, frameon=False)


def _hbar(ax, items, title):
    if not items:
        ax.axis("off")
        ax.set_title(title, fontsize=11)
        return
    labels = [d["label"] for d in items][::-1]
    values = [d["value"] for d in items][::-1]
    colors = (PALETTE * (len(items) // len(PALETTE) + 1))[:len(items)][::-1]
    ax.barh(labels, values, color=colors)
    ax.set_title(title, fontsize=11, pad=10)
    for i, v in enumerate(values):
        ax.text(v + max(values) * 0.02, i, str(v), va="center", fontsize=9)
    ax.set_xlim(0, max(values) * 1.15)


def export_metric_charts_png(data: dict, out_path: str):
    """Genera un PNG con todas las gráficas de métricas del dashboard."""
    charts = build_charts_data(data)

    fig, axes = plt.subplots(2, 3, figsize=(16, 9))
    fig.suptitle("Métricas globales — Análisis DNSSEC (MA2002B)", fontsize=15, y=0.98)

    _donut(axes[0, 0], charts["ds"], "Cadena DS íntegra")
    _donut(axes[0, 1], charts["dnskey"], "Dominios con DNSKEY")
    _donut(axes[0, 2], charts["rrsig"], "Estado de firmas RRSIG")
    _donut(axes[1, 0], charts["nsec"], "NSEC / NSEC3")
    _donut(axes[1, 1], charts["alg_status"], "Algoritmos: RFC 8624")
    _hbar(axes[1, 2], charts["alg_names"], "Algoritmos DNSKEY usados")

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def export_trust_tree_png(data: dict, out_path: str):
    """Genera un PNG del árbol de cadena de confianza usando networkx."""
    nodes = data["trust_tree"]["nodes"]
    edges = data["trust_tree"]["edges"]

    G = nx.DiGraph()
    for n in nodes:
        G.add_node(n)
    for e in edges:
        G.add_edge(e["parent"], e["child"])

    # Posiciones tipo árbol jerárquico (BFS por niveles)
    levels = {".": 0}
    order = list(nx.bfs_tree(G, "."))
    for n in order:
        for child in G.successors(n):
            levels[child] = levels.get(n, 0) + 1

    # Agrupar nodos por nivel para asignar x
    from collections import defaultdict
    by_level = defaultdict(list)
    for n in order:
        by_level[levels.get(n, 0)].append(n)

    pos = {}
    max_level = max(by_level.keys())
    for lvl, ns in by_level.items():
        for i, n in enumerate(ns):
            pos[n] = (i - (len(ns) - 1) / 2, -lvl)

    def node_color(n):
        if n == ".":
            return "#5b8def"
        info = nodes.get(n, {})
        has_dnskey = info.get("has_dnskey", False)
        has_ds     = info.get("has_ds", False)
        chain_ok   = info.get("trust_chain", False)
        if has_dnskey and has_ds and chain_ok:
            return "#36b37e"
        elif has_dnskey:
            return "#ffab00"
        return "#5a6478"

    colors = [node_color(n) for n in order]

    width  = max(14, len(by_level[max_level]) * 1.6)
    height = max(6, (max_level + 1) * 1.6)
    fig, ax = plt.subplots(figsize=(width, height))

    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#3a4a6b", arrows=False, width=1.4)
    nx.draw_networkx_nodes(G, pos, ax=ax, nodelist=order, node_color=colors,
                            node_size=420, edgecolors="#0f1420", linewidths=1.5)

    # Mover etiquetas debajo de cada nodo para no encimar
    for n in order:
        x, y = pos[n]
        ax.text(x, y - 0.25, n, ha="center", va="top", fontsize=7.5, color="#e6eaf2")

    ax.set_title("Árbol de cadena de confianza DNSSEC (raíz → dominios)", fontsize=13, pad=14)
    ax.axis("off")

    # Leyenda
    legend_items = [
        ("Raíz / ancla de confianza", "#5b8def"),
        ("DNSSEC OK (cadena íntegra)", "#36b37e"),
        ("Cadena incompleta / no verificable", "#ffab00"),
        ("Sin DNSSEC", "#5a6478"),
    ]
    handles = [plt.Line2D([0], [0], marker="o", color="w", label=l,
                           markerfacecolor=c, markersize=10, linestyle="")
               for l, c in legend_items]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.02),
              ncol=4, frameon=False, fontsize=9)

    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Uso: python generar_reporte.py dnssec_results.json [carpeta_salida]")
        sys.exit(1)

    json_path = sys.argv[1]
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(json_path).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    data = load_data(json_path)

    excel_path = out_dir / "resultados_dnssec.xlsx"
    html_path  = out_dir / "reporte_dnssec.html"
    metrics_png_path = out_dir / "metricas_dashboard.png"
    tree_png_path    = out_dir / "arbol_confianza.png"

    export_excel(data, str(excel_path))
    export_html(data, str(html_path))
    export_metric_charts_png(data, str(metrics_png_path))
    export_trust_tree_png(data, str(tree_png_path))

    print(f"Excel generado          : {excel_path}")
    print(f"HTML generado           : {html_path}")
    print(f"PNG métricas generado   : {metrics_png_path}")
    print(f"PNG árbol generado      : {tree_png_path}")


if __name__ == "__main__":
    main()
