"""VLAN Segmentation Audit Toolkit — Report Generation (HTML, JSON, CSV)"""

import csv
import json
import os
from datetime import datetime
from dataclasses import asdict

from jinja2 import Template

from config import (
    TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
    STATUS_FAIL, STATUS_WARN, STATUS_PASS, STATUS_INFO as ST_INFO, STATUS_SKIP, STATUS_ERROR,
    RISK_WEIGHTS, CRITICAL_PORTS,
)


HTML_TEMPLATE = Template(r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ meta.tool_name }} Report</title>
<style>
:root {
    --bg: #0d1117;
    --bg-card: #161b22;
    --bg-table-header: #1c2333;
    --bg-hover: #1f2937;
    --text: #e6edf3;
    --text-dim: #8b949e;
    --border: #30363d;
    --accent: #58a6ff;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #d29922;
    --orange: #db6d28;
    --blue: #58a6ff;
    --purple: #bc8cff;
    --cyan: #39d353;
    --port-open: #238636;
    --port-closed: #6e4040;
    --port-filtered: #30363d;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 16px; max-width: 1400px; margin: 0 auto; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { color: var(--accent); font-size: 1.8em; margin-bottom: 8px; }
h2 { color: var(--text); font-size: 1.4em; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
h3 { color: var(--text); font-size: 1.1em; margin: 16px 0 8px; }
.header { padding: 24px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px; }
.header .meta { display: flex; flex-wrap: wrap; gap: 24px; margin-top: 12px; color: var(--text-dim); font-size: 0.9em; }
.header .meta span { display: inline-block; }
.header .meta strong { color: var(--text); }

.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
.stat-card .value { font-size: 2em; font-weight: bold; }
.stat-card .label { font-size: 0.85em; color: var(--text-dim); margin-top: 4px; }
.stat-card.critical .value { color: var(--red); }
.stat-card.high .value { color: var(--orange); }
.stat-card.medium .value { color: var(--yellow); }
.stat-card.good .value { color: var(--green); }

.risk-bar { margin: 16px 0 24px; }
.risk-bar .bar-bg { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; height: 32px; overflow: hidden; }
.risk-bar .bar-fill { height: 100%; border-radius: 12px; transition: width 0.5s; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 0.85em; min-width: 60px; }
.risk-grade { text-align: center; margin: 8px 0; }
.risk-grade .grade { font-size: 3em; font-weight: bold; }

.matrix-wrap { overflow-x: auto; margin: 16px 0; }
table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
th, td { padding: 8px 10px; text-align: left; border: 1px solid var(--border); }
th { background: var(--bg-table-header); color: var(--text); position: sticky; top: 0; z-index: 1; white-space: nowrap; }
tr:hover { background: var(--bg-hover); }

.matrix-table { font-size: 0.75em; }
.matrix-table th { padding: 4px 6px; font-size: 0.85em; }
.matrix-table td { padding: 2px 4px; text-align: center; min-width: 32px; }
.matrix-table td.open { background: var(--port-open); color: #fff; font-weight: bold; }
.matrix-table td.closed { background: var(--port-closed); color: var(--text-dim); }
.matrix-table td.filtered { background: var(--port-filtered); color: var(--text-dim); }
.matrix-table .host-col { text-align: left; white-space: nowrap; font-family: monospace; position: sticky; left: 0; background: var(--bg-card); z-index: 2; }

.sev-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
.sev-CRITICAL { background: #5c1919; color: var(--red); }
.sev-HIGH { background: #5c3219; color: var(--orange); }
.sev-MEDIUM { background: #5c4919; color: var(--yellow); }
.sev-LOW { background: #193a5c; color: var(--blue); }
.sev-INFO { background: #1f2937; color: var(--text-dim); }

.status-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
.st-FAIL { background: #5c1919; color: var(--red); }
.st-WARN { background: #5c4919; color: var(--yellow); }
.st-PASS { background: #19431f; color: var(--green); }
.st-INFO { background: #193a5c; color: var(--blue); }
.st-SKIP { background: #1f2937; color: var(--text-dim); }
.st-ERROR { background: #5c1919; color: var(--red); }

.finding-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.finding-card.sev-border-CRITICAL { border-left: 4px solid var(--red); }
.finding-card.sev-border-HIGH { border-left: 4px solid var(--orange); }
.finding-card.sev-border-MEDIUM { border-left: 4px solid var(--yellow); }
.finding-card.sev-border-LOW { border-left: 4px solid var(--blue); }
.finding-card .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.finding-card .card-header h3 { margin: 0; }
.finding-card .detail-label { color: var(--text-dim); font-size: 0.85em; margin-top: 8px; }
.finding-card .detail-value { margin: 4px 0 8px; }
.finding-card .affected { font-family: monospace; font-size: 0.85em; color: var(--yellow); }

.host-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.host-card h3 { display: flex; align-items: center; gap: 8px; }
.host-card .os-badge { font-size: 0.8em; color: var(--text-dim); font-weight: normal; }
.host-card .port-list { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
.host-card .port-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-family: monospace; background: var(--port-open); color: #fff; }
.host-card .traceroute-hops { font-family: monospace; font-size: 0.85em; color: var(--text-dim); margin-top: 8px; }
.host-card .traceroute-hops .hop { display: flex; gap: 8px; padding: 2px 0; }

.top-risks { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 24px; }
.top-risks ol { padding-left: 20px; }
.top-risks li { margin: 8px 0; }

.nav { position: sticky; top: 0; z-index: 100; background: var(--bg); border-bottom: 1px solid var(--border); padding: 8px 0; margin-bottom: 16px; display: flex; flex-wrap: wrap; gap: 8px; }
.nav a { padding: 4px 12px; border-radius: 4px; font-size: 0.85em; color: var(--text-dim); background: var(--bg-card); border: 1px solid var(--border); }
.nav a:hover { color: var(--accent); border-color: var(--accent); text-decoration: none; }

.timing-table td:last-child { text-align: right; font-family: monospace; }
.footer { margin-top: 32px; padding: 16px; text-align: center; color: var(--text-dim); font-size: 0.85em; border-top: 1px solid var(--border); }
.collapsible { cursor: pointer; }
.collapsible::after { content: ' ▸'; }
.collapsible.open::after { content: ' ▾'; }
.collapse-body { display: none; }
.collapse-body.show { display: block; }

@media (max-width: 768px) {
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
    .header .meta { flex-direction: column; gap: 8px; }
}
</style>
</head>
<body>

<div class="nav">
    <a href="#summary">Summary</a>
    <a href="#matrix">Reachability</a>
    <a href="#hosts">Hosts</a>
    <a href="#findings-table">Findings</a>
    <a href="#details">Details</a>
    {% if vlan_findings %}<a href="#vlan-checks">VLAN Checks</a>{% endif %}
    {% if policy_findings %}<a href="#policy">Policy</a>{% endif %}
    <a href="#appendix">Appendix</a>
</div>

<div class="header">
    <h1>{{ meta.tool_name }}</h1>
    <div style="color: var(--text-dim); font-size: 0.95em;">VLAN Segmentation Audit Report — v{{ meta.tool_version }}</div>
    <div class="meta">
        <span><strong>Date:</strong> {{ scan_date }}</span>
        <span><strong>Source:</strong> {{ meta.source_ip }} ({{ meta.source_vlan }})</span>
        <span><strong>Gateway:</strong> {{ meta.gateway }}</span>
        <span><strong>Targets:</strong> {{ meta.targets }}</span>
        <span><strong>Speed:</strong> {{ meta.scan_speed }}</span>
        <span><strong>Duration:</strong> {{ meta.scan_duration }}s</span>
    </div>
</div>

<h2 id="summary">Executive Summary</h2>

<div class="summary-grid">
    <div class="stat-card">
        <div class="value">{{ total_targets }}</div>
        <div class="label">Targets Scanned</div>
    </div>
    <div class="stat-card good">
        <div class="value">{{ alive_hosts }}</div>
        <div class="label">Alive Hosts</div>
    </div>
    <div class="stat-card medium">
        <div class="value">{{ total_open_ports }}</div>
        <div class="label">Open Ports</div>
    </div>
    <div class="stat-card">
        <div class="value">{{ total_findings }}</div>
        <div class="label">Total Findings</div>
    </div>
    <div class="stat-card critical">
        <div class="value">{{ sev_counts.get('CRITICAL', 0) }}</div>
        <div class="label">Critical</div>
    </div>
    <div class="stat-card high">
        <div class="value">{{ sev_counts.get('HIGH', 0) }}</div>
        <div class="label">High</div>
    </div>
    <div class="stat-card medium">
        <div class="value">{{ sev_counts.get('MEDIUM', 0) }}</div>
        <div class="label">Medium</div>
    </div>
    <div class="stat-card">
        <div class="value">{{ sev_counts.get('LOW', 0) + sev_counts.get('INFO', 0) }}</div>
        <div class="label">Low / Info</div>
    </div>
</div>

<div class="risk-bar">
    <div class="risk-grade">
        <span class="grade" style="color: {{ risk_color }};">{{ risk_grade }}</span>
        <div style="color: var(--text-dim);">Risk Score: {{ risk_score }} / 100</div>
    </div>
    <div class="bar-bg">
        <div class="bar-fill" style="width: {{ risk_score }}%; background: {{ risk_color }};"></div>
    </div>
</div>

{% if top_risks %}
<div class="top-risks">
    <h3>Top Risks</h3>
    <ol>
    {% for f in top_risks %}
        <li><span class="sev-badge sev-{{ f.severity }}">{{ f.severity }}</span> <strong>{{ f.test_name }}</strong> — {{ f.description[:120] }}</li>
    {% endfor %}
    </ol>
</div>
{% endif %}

<h2 id="matrix">Reachability Matrix</h2>
<p style="color: var(--text-dim); margin-bottom: 12px;">TCP port reachability from {{ meta.source_ip }} ({{ meta.source_vlan }}). Green = OPEN, Dark red = CLOSED, Gray = FILTERED.</p>
<div class="matrix-wrap">
{% if matrix_hosts %}
<table class="matrix-table">
<thead>
<tr>
    <th class="host-col">Host</th>
    {% for p in matrix_ports %}<th>{{ p }}</th>{% endfor %}
</tr>
</thead>
<tbody>
{% for host in matrix_hosts %}
<tr>
    <td class="host-col">{{ host.ip }}{% if host.os_guess %} <span style="color:var(--text-dim)">({{ host.os_guess[:12] }})</span>{% endif %}</td>
    {% for p in matrix_ports %}
        {% if p in host.open_set %}
            <td class="open" title="{{ host.ip }}:{{ p }} OPEN">&#x25CF;</td>
        {% elif p in host.filtered_set %}
            <td class="filtered" title="{{ host.ip }}:{{ p }} FILTERED">&#x25CB;</td>
        {% else %}
            <td class="closed" title="{{ host.ip }}:{{ p }} CLOSED">&#x00B7;</td>
        {% endif %}
    {% endfor %}
</tr>
{% endfor %}
</tbody>
</table>
{% else %}
<p style="color: var(--text-dim);">No host reachability data collected.</p>
{% endif %}
</div>

<h2 id="hosts">Host Details</h2>
{% for host in host_results_alive %}
<div class="host-card">
    <h3>{{ host.ip }} {% if host.hostname %}<span class="os-badge">({{ host.hostname }})</span>{% endif %} <span class="os-badge">{{ host.os_guess }}</span></h3>
    {% if host.open_ports %}
    <div class="port-list">
        {% for p in host.open_ports %}
        <span class="port-tag" title="{{ host.services.get(p, '') }}">{{ p }}/tcp{% if host.services.get(p) %} {{ host.services[p][:15] }}{% endif %}</span>
        {% endfor %}
    </div>
    {% else %}
    <div style="color: var(--text-dim); font-size: 0.9em;">No open ports detected</div>
    {% endif %}
    {% if host.traceroute %}
    <div class="traceroute-hops">
        <strong>Traceroute ({{ host.hop_count }} hops):</strong>
        {% for hop in host.traceroute %}
        <div class="hop"><span style="color:var(--accent)">{{ loop.index }}.</span> {{ hop }}</div>
        {% endfor %}
    </div>
    {% endif %}
</div>
{% endfor %}
{% if not host_results_alive %}
<p style="color: var(--text-dim);">No alive hosts discovered.</p>
{% endif %}

<h2 id="findings-table">Findings Summary</h2>
<table>
<thead>
<tr>
    <th>ID</th>
    <th>Test Name</th>
    <th>Category</th>
    <th>Status</th>
    <th>Severity</th>
    <th>VLAN Path</th>
</tr>
</thead>
<tbody>
{% for f in all_findings %}
<tr>
    <td>{{ f.test_id }}</td>
    <td>{{ f.test_name }}</td>
    <td>{{ f.category }}</td>
    <td><span class="status-badge st-{{ f.status }}">{{ f.status }}</span></td>
    <td><span class="sev-badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
    <td>{{ f.source_vlan }}{% if f.target_vlan %} → {{ f.target_vlan }}{% endif %}</td>
</tr>
{% endfor %}
</tbody>
</table>

<h2 id="details">Detailed Findings</h2>
{% for f in actionable_findings %}
<div class="finding-card sev-border-{{ f.severity }}">
    <div class="card-header">
        <h3>{{ f.test_id }} — {{ f.test_name }}</h3>
        <div>
            <span class="status-badge st-{{ f.status }}">{{ f.status }}</span>
            <span class="sev-badge sev-{{ f.severity }}">{{ f.severity }}</span>
        </div>
    </div>
    <div class="detail-label">Description</div>
    <div class="detail-value">{{ f.description }}</div>
    {% if f.observation %}
    <div class="detail-label">Observation</div>
    <div class="detail-value">{{ f.observation }}</div>
    {% endif %}
    {% if f.remediation %}
    <div class="detail-label">Remediation</div>
    <div class="detail-value">{{ f.remediation }}</div>
    {% endif %}
    {% if f.affected_objects %}
    <div class="detail-label">Affected Objects ({{ f.affected_objects|length }})</div>
    <div class="detail-value">
        {% for obj in f.affected_objects[:50] %}
        <div class="affected">{{ obj }}</div>
        {% endfor %}
        {% if f.affected_objects|length > 50 %}
        <div style="color:var(--text-dim);">... and {{ f.affected_objects|length - 50 }} more</div>
        {% endif %}
    </div>
    {% endif %}
    {% if f.source_vlan or f.target_vlan %}
    <div class="detail-label">VLAN Path</div>
    <div class="detail-value">{{ f.source_vlan }} → {{ f.target_vlan }}</div>
    {% endif %}
</div>
{% endfor %}
{% if not actionable_findings %}
<p style="color: var(--green);">No FAIL or WARN findings — segmentation appears sound.</p>
{% endif %}

{% if vlan_findings %}
<h2 id="vlan-checks">VLAN Security Checks</h2>
{% for f in vlan_findings %}
<div class="finding-card sev-border-{{ f.severity }}">
    <div class="card-header">
        <h3>{{ f.test_id }} — {{ f.test_name }}</h3>
        <span class="status-badge st-{{ f.status }}">{{ f.status }}</span>
    </div>
    <div class="detail-value">{{ f.description }}</div>
    {% if f.observation %}<div class="detail-value" style="color:var(--text-dim);">{{ f.observation }}</div>{% endif %}
</div>
{% endfor %}
{% endif %}

{% if policy_findings %}
<h2 id="policy">Policy Compliance</h2>
{% for f in policy_findings %}
<div class="finding-card sev-border-{{ f.severity }}">
    <div class="card-header">
        <h3>{{ f.test_id }} — {{ f.test_name }}</h3>
        <span class="status-badge st-{{ f.status }}">{{ f.status }}</span>
    </div>
    <div class="detail-value">{{ f.description }}</div>
    {% if f.observation %}<div class="detail-value" style="color:var(--text-dim);">{{ f.observation }}</div>{% endif %}
</div>
{% endfor %}
{% endif %}

<h2 id="appendix">Appendix</h2>

<h3>Module Timing</h3>
<table class="timing-table" style="max-width:500px;">
<thead><tr><th>Module</th><th>Duration</th></tr></thead>
<tbody>
{% for mod, dur in meta.module_timings.items() %}
<tr><td>{{ mod }}</td><td>{{ dur }}s</td></tr>
{% endfor %}
</tbody>
</table>

<h3 style="margin-top:16px;">Scan Parameters</h3>
<table style="max-width:500px;">
<tbody>
<tr><td><strong>Source IP</strong></td><td>{{ meta.source_ip }}</td></tr>
<tr><td><strong>Source VLAN</strong></td><td>{{ meta.source_vlan }}</td></tr>
<tr><td><strong>Source Subnet</strong></td><td>{{ meta.source_subnet }}</td></tr>
<tr><td><strong>Gateway</strong></td><td>{{ meta.gateway }}</td></tr>
<tr><td><strong>Interface</strong></td><td>{{ meta.interface }}</td></tr>
<tr><td><strong>Targets</strong></td><td>{{ meta.targets }}</td></tr>
<tr><td><strong>Target Count</strong></td><td>{{ meta.target_count }}</td></tr>
<tr><td><strong>TCP Ports</strong></td><td>{{ meta.tcp_port_count }}</td></tr>
<tr><td><strong>UDP Ports</strong></td><td>{{ meta.udp_port_count }}</td></tr>
<tr><td><strong>Scan Speed</strong></td><td>{{ meta.scan_speed }}</td></tr>
<tr><td><strong>Total Duration</strong></td><td>{{ meta.scan_duration }}s</td></tr>
</tbody>
</table>

<div class="footer">
    {{ meta.tool_name }} v{{ meta.tool_version }} — Author: {{ meta.tool_author }}<br>
    Report generated: {{ scan_date }}
</div>

<script>
document.querySelectorAll('.collapsible').forEach(el => {
    el.addEventListener('click', () => {
        el.classList.toggle('open');
        const body = el.nextElementSibling;
        if (body) body.classList.toggle('show');
    });
});
</script>
</body>
</html>""")


def _risk_color(score):
    if score >= 80:
        return "#f85149"
    if score >= 60:
        return "#db6d28"
    if score >= 40:
        return "#d29922"
    if score >= 20:
        return "#3fb950"
    return "#3fb950"


def _risk_grade(score):
    if score >= 80:
        return "F"
    if score >= 60:
        return "D"
    if score >= 40:
        return "C"
    if score >= 20:
        return "B"
    return "A"


def generate_report(findings, host_results, metadata, output_path):
    """Generate dark-theme HTML report."""
    sev_counts = {}
    status_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        status_counts[f.status] = status_counts.get(f.status, 0) + 1

    alive = [h for h in host_results if h.is_alive]
    total_open = sum(len(h.open_ports) for h in host_results)

    actionable = [f for f in findings if f.status in (STATUS_FAIL, STATUS_WARN)]
    top_risks = sorted(
        actionable,
        key=lambda f: RISK_WEIGHTS.get(f.severity, 0),
        reverse=True,
    )[:5]

    vlan_findings = [f for f in findings if f.category in ("VLAN Checks", "VLAN Security")]
    policy_findings = [f for f in findings if f.category == "Policy Compliance"]

    all_open_ports = set()
    for h in host_results:
        all_open_ports.update(h.open_ports)
        all_open_ports.update(h.filtered_ports)
    matrix_ports = sorted(all_open_ports)[:130]

    matrix_hosts = []
    for h in alive:
        matrix_hosts.append({
            "ip": h.ip,
            "os_guess": h.os_guess,
            "open_set": set(h.open_ports),
            "filtered_set": set(h.filtered_ports),
        })

    risk_score = metadata.get("risk_score", 0)

    html = HTML_TEMPLATE.render(
        meta=metadata,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_targets=len(host_results),
        alive_hosts=len(alive),
        total_open_ports=total_open,
        total_findings=len(findings),
        sev_counts=sev_counts,
        status_counts=status_counts,
        risk_score=risk_score,
        risk_grade=_risk_grade(risk_score),
        risk_color=_risk_color(risk_score),
        top_risks=top_risks,
        matrix_ports=matrix_ports,
        matrix_hosts=matrix_hosts,
        host_results_alive=alive,
        all_findings=findings,
        actionable_findings=actionable,
        vlan_findings=vlan_findings,
        policy_findings=policy_findings,
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def generate_json_report(findings, host_results, metadata, output_path):
    """Generate JSON report."""
    def serialize_finding(f):
        return {
            "test_id": f.test_id,
            "test_name": f.test_name,
            "category": f.category,
            "status": f.status,
            "severity": f.severity,
            "description": f.description,
            "observation": f.observation,
            "remediation": f.remediation,
            "affected_objects": f.affected_objects,
            "details": f.details,
            "source_vlan": f.source_vlan,
            "target_vlan": f.target_vlan,
            "references": f.references,
        }

    def serialize_host(h):
        return {
            "ip": h.ip,
            "hostname": h.hostname,
            "is_alive": h.is_alive,
            "ttl": h.ttl,
            "os_guess": h.os_guess,
            "open_ports": h.open_ports,
            "filtered_ports": h.filtered_ports,
            "closed_ports": h.closed_ports,
            "services": h.services,
            "traceroute": h.traceroute,
            "hop_count": h.hop_count,
        }

    data = {
        "metadata": metadata,
        "findings": [serialize_finding(f) for f in findings],
        "hosts": [serialize_host(h) for h in host_results],
        "summary": {
            "total_targets": len(host_results),
            "alive_hosts": sum(1 for h in host_results if h.is_alive),
            "total_open_ports": sum(len(h.open_ports) for h in host_results),
            "total_findings": len(findings),
            "severity_counts": {},
        },
    }
    for f in findings:
        data["summary"]["severity_counts"][f.severity] = (
            data["summary"]["severity_counts"].get(f.severity, 0) + 1
        )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return output_path


def generate_csv_report(findings, output_path):
    """Generate CSV report of findings."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Test ID", "Test Name", "Category", "Status", "Severity",
            "Description", "Observation", "Remediation",
            "Affected Objects", "Source VLAN", "Target VLAN",
        ])
        for finding in findings:
            writer.writerow([
                finding.test_id,
                finding.test_name,
                finding.category,
                finding.status,
                finding.severity,
                finding.description,
                finding.observation,
                finding.remediation,
                "; ".join(finding.affected_objects) if finding.affected_objects else "",
                finding.source_vlan,
                finding.target_vlan,
            ])
    return output_path
