"""Turn a `diag` report dictionary into a single self-contained HTML file."""
import html

CSS = """
:root{--bg:#fff;--fg:#1c2330;--muted:#5b6678;--card:#f5f7fa;--line:#dde2ea;--ok:#1b7f4b;--bad:#b3261e;--bar:#3b7dd8}
@media(prefers-color-scheme:dark){:root{--bg:#10141b;--fg:#e6eaf0;--muted:#97a3b6;--card:#171d27;--line:#2a3342;--ok:#4cc38a;--bad:#ff7b72;--bar:#5a9bf0}}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:860px;margin:2rem auto;padding:0 1rem}
h1{margin-bottom:0}h2{margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.8rem 1rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}.ok{color:var(--ok)}.bad{color:var(--bad)}code{font-family:ui-monospace,monospace}
.bar{background:var(--bar);height:10px;border-radius:5px;min-width:2px}ul{padding-left:1.2rem}
"""


def e(value):
    return html.escape(str(value))


def table(headers, rows):
    if not rows:
        return '<p class="muted">No data.</p>'
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def render_html(report):
    parts = [f"<h1>Network diagnostic: {e(report['target'])}</h1>",
             f'<p class="muted">Generated {e(report.get("generated", ""))}</p>']

    findings = report.get("findings", [])
    if findings:
        items = "".join(f'<li class="bad">{e(f)}</li>' for f in findings)
        parts.append(f'<div class="card"><strong>Findings</strong><ul>{items}</ul></div>')
    else:
        parts.append('<div class="card ok"><strong>No problems detected.</strong></div>')

    info = report.get("info")
    if info:
        rows = [[e(k.replace("_", " ")), e(", ".join(v) if isinstance(v, list) else v or "unknown")]
                for k, v in info.items()]
        parts += ["<h2>This machine</h2>", table(["Item", "Value"], rows)]

    rows = []
    for r in report.get("dns", []):
        if "error" in r:
            rows.append([e(r["qtype"]), e(r["server"]), f'<span class="bad">{e(r["error"])}</span>', ""])
        else:
            answers = "<br>".join(e(a["data"]) for a in r["answers"]) or "(no records)"
            rows.append([e(r["qtype"]), e(r["server"]), answers, f'{r["elapsed_ms"]} ms'])
    parts += ["<h2>DNS</h2>", table(["Type", "Server", "Answer", "Time"], rows)]

    ping = report.get("ping", {})
    parts.append("<h2>TCP latency (port 443)</h2>")
    if "error" in ping:
        parts.append(f'<p class="bad">{e(ping["error"])}</p>')
    elif ping:
        stats = [["Sent / received", f'{ping["sent"]} / {ping["received"]}'],
                 ["Packet loss", f'{ping["loss_pct"]}%']]
        if ping["received"]:
            stats += [["Min / avg / max", f'{ping["min_ms"]} / {ping["avg_ms"]} / {ping["max_ms"]} ms'],
                      ["Jitter", f'{ping["jitter_ms"]} ms']]
        parts.append(table(["Metric", "Value"], [[e(a), e(b)] for a, b in stats]))

    web = report.get("http", {})
    parts.append("<h2>HTTPS</h2>")
    if "status" in web:
        parts.append(f'<p>{e(web["url"])} &rarr; <strong>{web["status"]} {e(web["reason"])}</strong></p>')
    else:
        parts.append(f'<p class="bad">{e(web.get("error", "no result"))}</p>')
    phases = {k: v for k, v in web.get("timings_ms", {}).items() if k != "total"}
    if phases:
        top = max(phases.values()) or 1
        rows = [[e(k), f'<div class="bar" style="width:{v / top * 100:.0f}%"></div>', f"{v} ms"]
                for k, v in phases.items()]
        parts.append(table(["Phase", "", "Time"], rows))
    if "cert_days_left" in web:
        parts.append(f'<p class="muted">Certificate expires in {web["cert_days_left"]} days.</p>')

    ports = report.get("ports", {})
    parts.append("<h2>Open ports</h2>")
    opened = [p for p in ports.get("results", []) if p["state"] == "open"]
    parts.append(table(["Port", "Service"], [[f'{p["port"]}/tcp', e(p["service"])] for p in opened]))
    if ports.get("counts"):
        c = ports["counts"]
        parts.append(f'<p class="muted">{ports["scanned"]} scanned: {c["open"]} open, '
                     f'{c["closed"]} closed, {c["filtered"]} filtered.</p>')

    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>netdiag report - {e(report["target"])}</title><style>{CSS}</style></head>'
            f'<body>{"".join(parts)}</body></html>')
