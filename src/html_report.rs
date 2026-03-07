//! HTML Dashboard Report Generator
//!
//! Produces a self-contained single HTML file with inline CSS/JS.
//! Accepts a `serde_json::Value` payload so it doesn't import from types.rs.

/// Generate a complete, self-contained HTML dashboard report.
///
/// `report_data` is expected to have this shape (all fields optional for resilience):
/// ```json
/// {
///   "direct_deps": [ { org, name, version, ... } ],
///   "transitive_deps": [ ... ],
///   "risk_flags": [ { dependency: {org,name,version}, severity, reason, cve_ids, risk_type } ],
///   "code_refs": { "coord": [ { file, line_number, line_content } ] },
///   "usage": [ { coord, version, verdict, import_files, usage_files, symbols_found, usage_count } ],
///   "graph_json": "..." // stringified JSON of the dep graph
/// }
/// ```
pub fn generate_html_report(report_data: &serde_json::Value) -> String {
    let direct = report_data
        .get("direct_deps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let transitive = report_data
        .get("transitive_deps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let flags = report_data
        .get("risk_flags")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let code_refs = report_data
        .get("code_refs")
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
    let usage = report_data
        .get("usage")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let graph_json = report_data
        .get("graph_json")
        .and_then(|v| v.as_str())
        .unwrap_or("{}");

    // Count severities
    let critical_count = flags.iter().filter(|f| sev_label(f) == "Critical").count();
    let high_count = flags.iter().filter(|f| sev_label(f) == "High").count();
    let medium_count = flags.iter().filter(|f| sev_label(f) == "Medium").count();
    let low_count = flags.iter().filter(|f| sev_label(f) == "Low").count();
    let info_count = flags.iter().filter(|f| sev_label(f) == "Info").count();

    // Usage pie data
    let active = usage
        .iter()
        .filter(|u| verdict_label(u) == "ACTIVE")
        .count();
    let dead_import = usage
        .iter()
        .filter(|u| verdict_label(u) == "DEAD IMPORT")
        .count();
    let unused = usage
        .iter()
        .filter(|u| verdict_label(u) == "UNUSED")
        .count();
    let runtime = usage
        .iter()
        .filter(|u| verdict_label(u) == "RUNTIME")
        .count();
    let total_usage = active + dead_import + unused + runtime;

    // Build risk flags table rows
    let mut risk_rows = String::new();
    for flag in &flags {
        let dep = flag.get("dependency").unwrap_or(flag);
        let org = dep.get("org").and_then(|v| v.as_str()).unwrap_or("?");
        let name = dep.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let version = dep.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let sev = sev_label(flag);
        let reason = flag.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        let risk_type = flag.get("risk_type").and_then(|v| v.as_str()).unwrap_or("");
        let cve_ids: Vec<String> = flag
            .get("cve_ids")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let cve_str = cve_ids.join(", ");
        let sev_class = sev.to_lowercase();
        let fix = flag
            .get("fix_suggestion")
            .and_then(|v| v.as_str())
            .unwrap_or("-");

        risk_rows.push_str(&format!(
            r#"<tr class="sev-{sev_class}">
  <td><span class="badge {sev_class}">{sev}</span></td>
  <td>{org}:{name}</td>
  <td>{version}</td>
  <td>{risk_type}</td>
  <td>{reason}</td>
  <td>{cve_str}</td>
  <td>{fix}</td>
</tr>
"#,
        ));
    }

    // Build dependency tree HTML
    let mut tree_html = String::new();
    for dep in &direct {
        let org = dep.get("org").and_then(|v| v.as_str()).unwrap_or("?");
        let name = dep.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let version = dep.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        tree_html.push_str(&format!(
            r#"<details class="dep-node">
  <summary>{org}:{name} <span class="ver">{version}</span></summary>
</details>
"#,
        ));
    }
    if !transitive.is_empty() {
        tree_html.push_str(r#"<details class="dep-node"><summary>Transitive dependencies</summary><div class="indent">"#);
        for dep in &transitive {
            let org = dep.get("org").and_then(|v| v.as_str()).unwrap_or("?");
            let name = dep.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let version = dep.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            tree_html.push_str(&format!(
                r#"<div class="dep-leaf">{org}:{name} <span class="ver">{version}</span></div>
"#,
            ));
        }
        tree_html.push_str("</div></details>\n");
    }

    // Build code references section
    let mut code_refs_html = String::new();
    if let Some(obj) = code_refs.as_object() {
        for (coord, refs) in obj {
            if let Some(arr) = refs.as_array() {
                code_refs_html.push_str(&format!(
                    r#"<details class="code-ref-group"><summary>{coord} ({} references)</summary><table class="code-ref-table"><tr><th>File</th><th>Line</th><th>Content</th></tr>"#,
                    arr.len()
                ));
                for r in arr {
                    let file = r.get("file").and_then(|v| v.as_str()).unwrap_or("?");
                    let line = r.get("line_number").and_then(|v| v.as_u64()).unwrap_or(0);
                    let content = r
                        .get("line_content")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;");
                    code_refs_html.push_str(&format!(
                        "<tr><td>{file}</td><td>{line}</td><td><code>{content}</code></td></tr>\n"
                    ));
                }
                code_refs_html.push_str("</table></details>\n");
            }
        }
    }

    // Build usage table rows
    let mut usage_rows = String::new();
    for u in &usage {
        let coord = u.get("coord").and_then(|v| v.as_str()).unwrap_or("?");
        let version = u.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let verdict = verdict_label(u);
        let usage_count = u.get("usage_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let symbols: Vec<String> = u
            .get("symbols_found")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let verdict_class = verdict.to_lowercase().replace(' ', "-");
        usage_rows.push_str(&format!(
            r#"<tr class="verdict-{verdict_class}">
  <td>{coord}</td>
  <td>{version}</td>
  <td><span class="badge {verdict_class}">{verdict}</span></td>
  <td>{usage_count}</td>
  <td>{}</td>
</tr>
"#,
            symbols.join(", ")
        ));
    }

    // Pie chart segments (CSS conic-gradient)
    let pie_gradient = if total_usage > 0 {
        let pct = |n: usize| -> f64 { (n as f64 / total_usage as f64) * 100.0 };
        let p1 = pct(active);
        let p2 = p1 + pct(dead_import);
        let p3 = p2 + pct(unused);
        format!(
            "conic-gradient(#4caf50 0% {p1:.1}%, #ff9800 {p1:.1}% {p2:.1}%, #f44336 {p2:.1}% {p3:.1}%, #9e9e9e {p3:.1}% 100%)"
        )
    } else {
        "conic-gradient(#444 0% 100%)".to_string()
    };

    // Assemble HTML
    let html = HTML_TEMPLATE
        .replace("{{CRITICAL_COUNT}}", &critical_count.to_string())
        .replace("{{HIGH_COUNT}}", &high_count.to_string())
        .replace("{{MEDIUM_COUNT}}", &medium_count.to_string())
        .replace("{{LOW_COUNT}}", &low_count.to_string())
        .replace("{{INFO_COUNT}}", &info_count.to_string())
        .replace("{{DIRECT_COUNT}}", &direct.len().to_string())
        .replace("{{TRANSITIVE_COUNT}}", &transitive.len().to_string())
        .replace("{{TOTAL_FLAGS}}", &flags.len().to_string())
        .replace("{{RISK_TABLE_ROWS}}", &risk_rows)
        .replace("{{DEPENDENCY_TREE}}", &tree_html)
        .replace("{{CODE_REFS}}", &code_refs_html)
        .replace("{{USAGE_TABLE_ROWS}}", &usage_rows)
        .replace("{{PIE_GRADIENT}}", &pie_gradient)
        .replace("{{ACTIVE_COUNT}}", &active.to_string())
        .replace("{{DEAD_IMPORT_COUNT}}", &dead_import.to_string())
        .replace("{{UNUSED_COUNT}}", &unused.to_string())
        .replace("{{RUNTIME_COUNT}}", &runtime.to_string())
        .replace("{{GRAPH_JSON}}", graph_json);

    html
}

fn sev_label(flag: &serde_json::Value) -> String {
    flag.get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("Info")
        .to_string()
}

fn verdict_label(u: &serde_json::Value) -> String {
    u.get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_string()
}

const HTML_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>scala-dep-scan Report</title>
<style>
  :root {
    --bg: #1a1a2e;
    --surface: #16213e;
    --surface2: #0f3460;
    --text: #e0e0e0;
    --text-muted: #a0a0a0;
    --critical: #ff1744;
    --high: #ff5722;
    --medium: #ff9800;
    --low: #ffc107;
    --info: #2196f3;
    --accent: #00e5ff;
    --green: #4caf50;
    --border: #2a2a4a;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 2rem;
    line-height: 1.6;
  }
  h1 { color: var(--accent); margin-bottom: 0.5rem; font-size: 1.8rem; }
  h2 { color: var(--accent); margin: 2rem 0 1rem; font-size: 1.3rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .subtitle { color: var(--text-muted); margin-bottom: 2rem; }

  /* Summary cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
  .card {
    background: var(--surface);
    border-radius: 8px;
    padding: 1.2rem;
    text-align: center;
    border-left: 4px solid var(--border);
  }
  .card .count { font-size: 2.2rem; font-weight: 700; }
  .card .label { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .card.critical { border-left-color: var(--critical); }
  .card.critical .count { color: var(--critical); }
  .card.high { border-left-color: var(--high); }
  .card.high .count { color: var(--high); }
  .card.medium { border-left-color: var(--medium); }
  .card.medium .count { color: var(--medium); }
  .card.low { border-left-color: var(--low); }
  .card.low .count { color: var(--low); }
  .card.info { border-left-color: var(--info); }
  .card.info .count { color: var(--info); }
  .card.deps { border-left-color: var(--accent); }
  .card.deps .count { color: var(--accent); }

  /* Tables */
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--surface2); color: var(--accent); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; position: sticky; top: 0; cursor: pointer; }
  th:hover { background: #1a4a80; }
  tr:hover { background: rgba(0,229,255,0.05); }
  td code { background: var(--surface2); padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .badge.critical { background: var(--critical); color: #fff; }
  .badge.high { background: var(--high); color: #fff; }
  .badge.medium { background: var(--medium); color: #000; }
  .badge.low { background: var(--low); color: #000; }
  .badge.info { background: var(--info); color: #fff; }
  .badge.active { background: var(--green); color: #fff; }
  .badge.dead-import { background: var(--medium); color: #000; }
  .badge.unused { background: var(--critical); color: #fff; }
  .badge.runtime { background: #9e9e9e; color: #000; }

  /* Dependency tree */
  .dep-node { margin: 0.3rem 0; }
  .dep-node summary { cursor: pointer; padding: 0.3rem 0.6rem; border-radius: 4px; }
  .dep-node summary:hover { background: var(--surface); }
  .dep-leaf { padding: 0.2rem 0.6rem 0.2rem 1.5rem; color: var(--text-muted); }
  .indent { margin-left: 1.5rem; }
  .ver { color: var(--text-muted); font-size: 0.85rem; }

  /* Code refs */
  .code-ref-group { margin: 0.5rem 0; }
  .code-ref-group summary { cursor: pointer; padding: 0.3rem; border-radius: 4px; }
  .code-ref-group summary:hover { background: var(--surface); }
  .code-ref-table { font-size: 0.85rem; }

  /* Pie chart */
  .pie-container { display: flex; align-items: center; gap: 2rem; margin: 1.5rem 0; flex-wrap: wrap; }
  .pie {
    width: 180px;
    height: 180px;
    border-radius: 50%;
    background: {{PIE_GRADIENT}};
    flex-shrink: 0;
  }
  .legend-item { display: flex; align-items: center; gap: 0.5rem; margin: 0.3rem 0; }
  .legend-swatch { width: 14px; height: 14px; border-radius: 3px; flex-shrink: 0; }

  /* Search */
  .search-box { margin: 1rem 0; }
  .search-box input {
    width: 100%;
    max-width: 400px;
    padding: 0.5rem 1rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
    color: var(--text);
    font-size: 0.9rem;
  }
  .search-box input:focus { outline: none; border-color: var(--accent); }

  /* Footer */
  .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.8rem; }
</style>
</head>
<body>

<h1>scala-dep-scan Dashboard</h1>
<p class="subtitle">Dependency Risk Analysis Report</p>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<div class="cards">
  <div class="card critical"><div class="count">{{CRITICAL_COUNT}}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="count">{{HIGH_COUNT}}</div><div class="label">High</div></div>
  <div class="card medium"><div class="count">{{MEDIUM_COUNT}}</div><div class="label">Medium</div></div>
  <div class="card low"><div class="count">{{LOW_COUNT}}</div><div class="label">Low</div></div>
  <div class="card info"><div class="count">{{INFO_COUNT}}</div><div class="label">Info</div></div>
  <div class="card deps"><div class="count">{{DIRECT_COUNT}}</div><div class="label">Direct Deps</div></div>
  <div class="card deps"><div class="count">{{TRANSITIVE_COUNT}}</div><div class="label">Transitive Deps</div></div>
</div>

<!-- Risk Findings -->
<h2>Risk Findings ({{TOTAL_FLAGS}} total)</h2>
<div class="search-box">
  <input type="text" id="risk-search" placeholder="Search findings..." onkeyup="filterTable('risk-search','risk-table')">
</div>
<div style="overflow-x:auto">
<table id="risk-table">
  <thead>
    <tr>
      <th onclick="sortTable('risk-table',0)">Severity</th>
      <th onclick="sortTable('risk-table',1)">Dependency</th>
      <th onclick="sortTable('risk-table',2)">Version</th>
      <th onclick="sortTable('risk-table',3)">Type</th>
      <th onclick="sortTable('risk-table',4)">Reason</th>
      <th onclick="sortTable('risk-table',5)">CVEs</th>
      <th onclick="sortTable('risk-table',6)">Fix</th>
    </tr>
  </thead>
  <tbody>
{{RISK_TABLE_ROWS}}
  </tbody>
</table>
</div>

<!-- Dependency Tree -->
<h2>Dependency Tree</h2>
<div class="dep-tree">
{{DEPENDENCY_TREE}}
</div>

<!-- Usage Analysis -->
<h2>Usage Analysis</h2>
<div class="pie-container">
  <div class="pie"></div>
  <div class="legend">
    <div class="legend-item"><div class="legend-swatch" style="background:#4caf50"></div> Active: {{ACTIVE_COUNT}}</div>
    <div class="legend-item"><div class="legend-swatch" style="background:#ff9800"></div> Dead Import: {{DEAD_IMPORT_COUNT}}</div>
    <div class="legend-item"><div class="legend-swatch" style="background:#f44336"></div> Unused: {{UNUSED_COUNT}}</div>
    <div class="legend-item"><div class="legend-swatch" style="background:#9e9e9e"></div> Runtime Only: {{RUNTIME_COUNT}}</div>
  </div>
</div>
<div style="overflow-x:auto">
<table id="usage-table">
  <thead>
    <tr>
      <th onclick="sortTable('usage-table',0)">Dependency</th>
      <th onclick="sortTable('usage-table',1)">Version</th>
      <th onclick="sortTable('usage-table',2)">Verdict</th>
      <th onclick="sortTable('usage-table',3)">Usage Count</th>
      <th>Symbols</th>
    </tr>
  </thead>
  <tbody>
{{USAGE_TABLE_ROWS}}
  </tbody>
</table>
</div>

<!-- Code References -->
<h2>Code References</h2>
{{CODE_REFS}}

<div class="footer">
  Generated by <strong>scala-dep-scan</strong>
</div>

<script>
function sortTable(tableId, col) {
  var table = document.getElementById(tableId);
  var tbody = table.querySelector('tbody');
  var rows = Array.from(tbody.querySelectorAll('tr'));
  var asc = table.dataset['sort'+col] !== 'asc';
  table.dataset['sort'+col] = asc ? 'asc' : 'desc';
  rows.sort(function(a, b) {
    var at = (a.cells[col]||{}).textContent||'';
    var bt = (b.cells[col]||{}).textContent||'';
    var an = parseFloat(at), bn = parseFloat(bt);
    if (!isNaN(an) && !isNaN(bn)) return asc ? an-bn : bn-an;
    return asc ? at.localeCompare(bt) : bt.localeCompare(at);
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
}
function filterTable(inputId, tableId) {
  var q = document.getElementById(inputId).value.toLowerCase();
  var rows = document.getElementById(tableId).querySelector('tbody').querySelectorAll('tr');
  rows.forEach(function(r) {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_report() {
        let data = serde_json::json!({});
        let html = generate_html_report(&data);
        assert!(html.contains("scala-dep-scan Dashboard"));
        assert!(html.contains("Executive Summary"));
    }

    #[test]
    fn test_report_with_flags() {
        let data = serde_json::json!({
            "direct_deps": [
                {"org": "com.typesafe.play", "name": "play-json", "version": "2.6.14"}
            ],
            "risk_flags": [
                {
                    "dependency": {"org": "com.typesafe.play", "name": "play-json", "version": "2.6.14"},
                    "severity": "High",
                    "reason": "Outdated dependency",
                    "risk_type": "OUTDATED",
                    "cve_ids": []
                }
            ]
        });
        let html = generate_html_report(&data);
        assert!(html.contains("play-json"));
        assert!(html.contains("Outdated dependency"));
    }
}
