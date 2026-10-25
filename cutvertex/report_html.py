"""Self-contained HTML report renderer.

No CDN, no external fonts, no JavaScript dependencies beyond the browser
itself. A security report that phones home to a third party or cannot be
opened on an air-gapped review laptop is not a usable report. Everything is
inlined so a single file is the whole deliverable.

All interpolated content is inserted via ``textContent`` / DOM APIs in the
embedded script, and the JSON payload is escaped for safe embedding in a
``<script type="application/json">`` block, so asset names containing markup
cannot become script.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import json

_CSS = r"""
:root{
  --bg:#0b0e14; --bg2:#11161f; --panel:#151b26; --panel2:#1b2330;
  --line:#242e3d; --line2:#2f3b4d;
  --fg:#e6edf6; --fg2:#a7b4c6; --fg3:#6f7d92;
  --act:#ff4d6d; --attend:#ffa63d; --track:#4d9fff; --trackstar:#b98cff;
  --ok:#2ee6a8; --warn:#ffcc55;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);font-family:var(--sans);
  -webkit-font-smoothing:antialiased;line-height:1.5}
body{padding:32px 20px 80px}
.wrap{max-width:1180px;margin:0 auto}
header.top{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;
  padding-bottom:22px;border-bottom:1px solid var(--line);margin-bottom:28px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:13px}
.mark{width:40px;height:40px;border-radius:11px;flex:0 0 auto;
  background:linear-gradient(135deg,#2ee6a8,#4d9fff 55%,#b98cff);
  display:grid;place-items:center;font-weight:800;font-size:17px;color:#08111a;
  box-shadow:0 4px 18px rgba(77,159,255,.28)}
h1{font-size:21px;margin:0;letter-spacing:-.3px}
h1 span{color:var(--fg3);font-weight:500}
.sub{font-size:12.5px;color:var(--fg3);margin-top:3px;font-family:var(--mono)}
.meta{text-align:right;font-size:12px;color:var(--fg3);font-family:var(--mono);line-height:1.75}
.meta b{color:var(--fg2);font-weight:600}

.grid{display:grid;gap:13px;margin-bottom:26px}
.k4{grid-template-columns:repeat(auto-fit,minmax(168px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:15px 16px}
.kpi .lbl{font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--fg3);
  font-weight:600;margin-bottom:7px}
.kpi .val{font-size:27px;font-weight:700;letter-spacing:-1px;font-variant-numeric:tabular-nums}
.kpi .hint{font-size:11.5px;color:var(--fg3);margin-top:3px}
.kpi.lead .val{background:linear-gradient(120deg,#2ee6a8,#4d9fff);-webkit-background-clip:text;
  background-clip:text;color:transparent}

section{margin-bottom:34px}
h2{font-size:14px;margin:0 0 4px;letter-spacing:.02em;display:flex;align-items:center;gap:9px}
h2:before{content:"";width:3px;height:15px;border-radius:2px;background:var(--ok)}
.secdesc{font-size:12.5px;color:var(--fg3);margin:0 0 15px 12px;max-width:80ch}

.bar{height:7px;border-radius:4px;background:var(--line);overflow:hidden;display:flex}
.bar i{display:block;height:100%}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:11.5px;color:var(--fg3);margin-top:10px}
.legend b{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}

table{width:100%;border-collapse:collapse;font-size:12.8px}
thead th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;
  color:var(--fg3);font-weight:600;padding:0 10px 9px;border-bottom:1px solid var(--line)}
tbody td{padding:10px;border-bottom:1px solid #1b2230;vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:#131a25}
.mono{font-family:var(--mono);font-size:11.5px}
.pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:10.5px;font-weight:700;
  letter-spacing:.05em;text-transform:uppercase;white-space:nowrap}
.p-act{background:rgba(255,77,109,.16);color:var(--act);border:1px solid rgba(255,77,109,.35)}
.p-attend{background:rgba(255,166,61,.15);color:var(--attend);border:1px solid rgba(255,166,61,.33)}
.p-track\*{background:rgba(185,140,255,.14);color:var(--trackstar);border:1px solid rgba(185,140,255,.32)}
.p-track{background:rgba(77,159,255,.13);color:var(--track);border:1px solid rgba(77,159,255,.3)}
.chip{display:inline-block;padding:1px 7px;border-radius:5px;background:var(--panel2);
  border:1px solid var(--line2);font-family:var(--mono);font-size:10.5px;color:var(--fg2);margin:1px 3px 1px 0}
.chain{font-family:var(--mono);font-size:11.5px;color:var(--fg2);word-break:break-word}
.chain em{color:var(--ok);font-style:normal;font-weight:600}
.chain s{color:var(--fg3);text-decoration:none}
.score{font-family:var(--mono);font-weight:700;font-variant-numeric:tabular-nums}
.cp{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;
  margin-bottom:10px;display:grid;grid-template-columns:26px 1fr auto;gap:14px;align-items:start}
.cp .rank{font-family:var(--mono);font-size:17px;font-weight:700;color:var(--fg3);padding-top:1px}
.cp .t{font-family:var(--mono);font-size:13px;color:var(--fg);margin-bottom:5px}
.cp .why{font-size:12px;color:var(--fg3);line-height:1.55}
.cp .impact{text-align:right;min-width:118px}
.cp .impact .n{font-size:19px;font-weight:700;color:var(--ok);font-variant-numeric:tabular-nums}
.cp .impact .s{font-size:10.5px;color:var(--fg3);text-transform:uppercase;letter-spacing:.07em}
.cp .fix{font-size:11.5px;color:var(--warn);font-family:var(--mono);margin-top:5px}
.meter{height:4px;background:var(--line);border-radius:3px;margin-top:8px;overflow:hidden}
.meter i{display:block;height:100%;background:linear-gradient(90deg,#2ee6a8,#4d9fff)}
.note{background:rgba(255,204,85,.07);border:1px solid rgba(255,204,85,.24);border-radius:10px;
  padding:11px 14px;font-size:12.5px;color:#e8d9a8;margin-bottom:9px}
.note.err{background:rgba(255,77,109,.07);border-color:rgba(255,77,109,.26);color:#f3b9c3}
.empty{color:var(--fg3);font-size:13px;padding:16px;text-align:center;
  border:1px dashed var(--line2);border-radius:10px}
footer{border-top:1px solid var(--line);margin-top:44px;padding-top:16px;
  font-size:11px;color:var(--fg3);font-family:var(--mono);display:flex;
  justify-content:space-between;gap:16px;flex-wrap:wrap}
@media(max-width:720px){
  body{padding:20px 13px 50px}
  .cp{grid-template-columns:1fr;gap:9px}
  .cp .impact{text-align:left}
  .meta{text-align:left}
  table{font-size:12px}
  thead{display:none}
  tbody td{display:block;border:none;padding:3px 0}
  tbody tr{display:block;border-bottom:1px solid #1b2230;padding:9px 0}
}
@media print{
  body{background:#fff;color:#111;padding:0}
  .card,.cp{background:#fff;border-color:#ccc}
  h2:before{background:#333}
  .kpi .val{color:#111!important;-webkit-text-fill-color:#111}
}
"""

_JS = r"""
(function(){
  var raw = document.getElementById('cv-data').textContent;
  var d;
  try { d = JSON.parse(raw); } catch(e){
    document.getElementById('app').innerHTML =
      '<div class="note err">Report payload could not be parsed: ' +
      String(e.message).replace(/[<>&]/g,'') + '</div>';
    return;
  }
  function el(tag, cls, txt){
    var n = document.createElement(tag);
    if(cls) n.className = cls;
    if(txt !== undefined && txt !== null) n.textContent = String(txt);
    return n;
  }
  function pill(p){
    var s = String(p||'track');
    return el('span','pill p-'+s.replace('*','\\*'), s.toUpperCase());
  }
  function num(v, dp){
    if(v===null||v===undefined) return '\u2014';
    return Number(v).toFixed(dp===undefined?1:dp);
  }

  var s = d.summary || {};

  // ---- overview KPIs
  var kpis = [
    ['Exposure Index', num(d.exposure_index,1)+'/100', 'top-path weighted', true],
    ['Attack Paths', s.paths||0, (s.realizable_paths||0)+' externally realizable'],
    ['Act Priority', s.priority_act||0, 'SLA 3 days'],
    ['Chokepoints', s.chokepoints||0, 'single-change fixes'],
    ['Assets', s.nodes||0, (s.entry_points||0)+' entry \u00b7 '+(s.crown_jewels||0)+' crown jewels']
  ];
  var kg = document.getElementById('kpis');
  kpis.forEach(function(k){
    var c = el('div','card kpi'+(k[3]?' lead':''));
    c.appendChild(el('div','lbl',k[0]));
    c.appendChild(el('div','val',k[1]));
    c.appendChild(el('div','hint',k[2]));
    kg.appendChild(c);
  });

  // ---- priority distribution
  var dist = [
    ['act', s.priority_act||0],
    ['attend', s.priority_attend||0],
    ['track*', s['priority_track*']||0],
    ['track', s.priority_track||0]
  ];
  var total = dist.reduce(function(a,b){return a+b[1];},0);
  if(total>0){
    var bar = el('div','bar'); var leg = el('div','legend');
    var cols = {act:'var(--act)',attend:'var(--attend)','track*':'var(--trackstar)','track':'var(--track)'};
    dist.forEach(function(x){
      if(x[1]>0){
        var i = el('i'); i.style.width = (100*x[1]/total)+'%'; i.style.background = cols[x[0]];
        bar.appendChild(i);
      }
      var l = el('span');
      var b = el('b'); b.style.background = cols[x[0]];
      l.appendChild(b); l.appendChild(document.createTextNode(x[0].toUpperCase()+' '+x[1]));
      leg.appendChild(l);
    });
    document.getElementById('dist').appendChild(bar);
    document.getElementById('dist').appendChild(leg);
  } else {
    document.getElementById('dist').appendChild(el('div','empty','No findings to distribute.'));
  }

  // ---- warnings
  var wn = document.getElementById('warnings');
  var warns = d.warnings || [];
  if(warns.length){
    warns.forEach(function(w){ wn.appendChild(el('div','note',w)); });
  } else {
    wn.appendChild(el('div','note','No structural warnings: graph passed validation and at least one path reaches a crown jewel.'));
  }

  // ---- chokepoints
  var cps = d.chokepoints || [];
  var cg = document.getElementById('chokes');
  if(!cps.length){
    cg.appendChild(el('div','empty','No chokepoints: no attacker path currently reaches a crown jewel.'));
  }
  cps.forEach(function(c,i){
    var row = el('div','cp');
    row.appendChild(el('div','rank',i+1));
    var mid = el('div');
    mid.appendChild(el('div','t', c.edge.src + ' \u2192 ' + c.edge.dst));
    mid.appendChild(el('div','why', c.rationale || ''));
    var fix = el('div','fix','\u2192 ' + (c.cost_hint||''));
    mid.appendChild(fix);
    row.appendChild(mid);
    var im = el('div','impact');
    im.appendChild(el('div','n', c.paths_broken + '/' + c.paths_total));
    im.appendChild(el('div','s','paths broken'));
    var m = el('div','meter'); var mi = el('i');
    mi.style.width = Math.max(2, Math.min(100, (c.risk_share||0)*100)) + '%';
    m.appendChild(mi); im.appendChild(m);
    im.appendChild(el('div','s', (num((c.risk_share||0)*100,0))+'% of risk'));
    row.appendChild(im);
    cg.appendChild(row);
  });

  // ---- findings table
  var fs = d.findings || [];
  var ft = document.getElementById('findings');
  if(!fs.length){
    ft.appendChild(el('div','empty','No findings supplied with this assessment.'));
  } else {
    var tbl = el('table');
    var thead = el('thead'); var htr = el('tr');
    ['Priority','Risk','ID','Asset','Issue','Signals','SLA'].forEach(function(h){
      htr.appendChild(el('th',null,h));
    });
    thead.appendChild(htr); tbl.appendChild(thead);
    var tb = el('tbody');
    fs.forEach(function(f){
      var tr = el('tr');
      var td0 = el('td'); td0.appendChild(pill(f.priority)); tr.appendChild(td0);
      var td1 = el('td','score'); td1.textContent = num(f.risk_score,1); tr.appendChild(td1);
      tr.appendChild(el('td','mono', f.id));
      var tdA = el('td'); tdA.appendChild(el('div',null,f.asset_name||f.asset));
      var tags = el('div');
      if(f.on_verified_path){ var c1 = el('span','chip','on-path x'+f.contributing_paths); tags.appendChild(c1); }
      if(f.cve){ tags.appendChild(el('span','chip',f.cve)); }
      tdA.appendChild(tags); tr.appendChild(tdA);
      tr.appendChild(el('td',null, f.title||'\u2014'));
      var tdS = el('td');
      if(f.cvss!==null&&f.cvss!==undefined) tdS.appendChild(el('span','chip','CVSS '+num(f.cvss,1)));
      if(f.epss!==null&&f.epss!==undefined) tdS.appendChild(el('span','chip','EPSS '+num(f.epss,3)));
      if(f.kev) tdS.appendChild(el('span','chip','KEV'));
      if(f.patch_available===false) tdS.appendChild(el('span','chip','no patch'));
      tr.appendChild(tdS);
      tr.appendChild(el('td','mono', f.sla_days+'d'));
      tb.appendChild(tr);
    });
    tbl.appendChild(tb); ft.appendChild(tbl);
  }

  // ---- paths
  var ps = d.paths || [];
  var pg = document.getElementById('paths');
  if(!ps.length){
    pg.appendChild(el('div','empty','No attacker path found under the modelled preconditions.'));
  }
  ps.slice(0,12).forEach(function(p){
    var row = el('div','cp');
    var sc = el('div','rank'); sc.textContent = num(p.score,0); row.appendChild(sc);
    var mid = el('div');
    var chain = el('div','chain');
    var ids = [p.entry];
    (p.steps||[]).forEach(function(st){ ids.push(st.dst); });
    ids.forEach(function(id,ix){
      chain.appendChild(document.createTextNode(id));
      if(ix < ids.length-1) chain.appendChild(el('s','',' \u2192 '));
    });
    mid.appendChild(chain);
    var meta = el('div','why');
    meta.textContent = p.hops + ' hops \u00b7 ' + (p.realizable ? 'externally realizable' : 'needs prior foothold') +
      (p.residual_gaps && p.residual_gaps.length ? ' \u00b7 gaps: ' + p.residual_gaps.join(', ') : '');
    mid.appendChild(meta);
    row.appendChild(mid);
    var im = el('div','impact');
    im.appendChild(el('div','n', p.hops));
    im.appendChild(el('div','s','hops'));
    im.appendChild(el('div','s', p.realizable ? 'REALIZABLE' : 'GATED'));
    row.appendChild(im);
    pg.appendChild(row);
  });

  // ---- footer stamp
  document.getElementById('stamp').textContent = 'generated ' + (d.generated_at||'');
})();
"""


def _json_for_html(payload: dict) -> str:
    """Serialise for embedding in a script block without allowing tag break-out."""
    text = json.dumps(payload, ensure_ascii=False)
    # Prevent premature </script> termination and HTML-comment openers.
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_html(payload: dict) -> str:
    """Render a complete, dependency-free HTML report for one assessment."""
    summary = payload.get("summary", {})
    title = payload.get("title", "Attack Path Assessment")
    data = _json_for_html(payload)
    exposure = payload.get("exposure_index", 0.0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>CutVertex \u2014 {_esc(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <div class="mark">CV</div>
      <div>
        <h1>CutVertex <span>\u2014 {_esc(title)}</span></h1>
        <div class="sub">precondition-aware attack path analysis</div>
      </div>
    </div>
    <div class="meta">
      <div>exposure index <b>{exposure}</b>/100</div>
      <div>{summary.get('nodes', 0)} assets &middot; {summary.get('edges', 0)} edges</div>
      <div>{summary.get('paths', 0)} paths &middot; {summary.get('findings', 0)} findings</div>
    </div>
  </header>

  <div class="grid k4" id="kpis"></div>

  <section>
    <h2>Priority distribution</h2>
    <p class="secdesc">Findings categorised by the deployer decision tree: exploitation
      evidence first, then exposure, then automatability, then mission impact.</p>
    <div class="card" id="dist"></div>
  </section>

  <section>
    <h2>Structural notes</h2>
    <div id="warnings"></div>
  </section>

  <section>
    <h2>Remediation chokepoints</h2>
    <p class="secdesc">Ranked by verified risk weight removed if that single edge is closed.
      The count is an exact recomputation, not an estimate.</p>
    <div id="chokes"></div>
  </section>

  <section>
    <h2>Prioritised findings</h2>
    <p class="secdesc">Composite of severity (CVSS), likelihood (EPSS/KEV/exploit maturity),
      asset criticality and graph exposure. Risk is not a severity re-ranking.</p>
    <div class="card" style="padding:14px 10px" id="findings"></div>
  </section>

  <section>
    <h2>Top attack paths</h2>
    <p class="secdesc">Ordered by plausibility. A path marked GATED requires an inherited
      capability the attacker must already hold to start.</p>
    <div id="paths"></div>
  </section>

  <footer>
    <span>CutVertex \u00a9 2026 kk (kkdev9715) &middot; All Rights Reserved</span>
    <span id="stamp"></span>
  </footer>
</div>

<script type="application/json" id="cv-data">{data}</script>
<script>{_JS}</script>
</body>
</html>
"""


def _esc(text: object) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
