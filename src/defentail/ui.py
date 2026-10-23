"""Local, single-user browser interface, 127.0.0.1 only; never serves project files."""
from __future__ import annotations

import html
import json
import secrets
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import doctor, scan
from .intelligence import bundled_data, kev_status

STYLE = """
:root { font: 15px system-ui,-apple-system,Segoe UI,sans-serif; color:#1c1b19; background:#f5f4f1; }
* {box-sizing:border-box} body{margin:0} .wrap{max-width:940px;margin:auto;padding:28px 20px 80px}
header{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:48px}
a{color:#2d2c29} .logo{font-size:18px;font-weight:800;letter-spacing:-.04em} .muted{color:#66645f}
.hero{font-size:clamp(32px,7vw,58px);font-weight:760;line-height:1.03;letter-spacing:-.06em;max-width:700px;margin:0 0 16px}
.lead{font-size:17px;line-height:1.55;max-width:650px;color:#56544e}
.panel{background:white;border:1px solid #dcdad5;border-radius:18px;padding:22px;margin:26px 0;box-shadow:0 4px 32px #00000006}
label{display:block;font-size:13px;font-weight:700;margin:15px 0 7px}
input,select{font:inherit;background:#fff;border:1px solid #bebbb5;border-radius:9px;padding:12px;width:100%}
button,.btn{font:inherit;border:0;background:#1e1d1b;color:white;border-radius:9px;padding:12px 22px;cursor:pointer;font-weight:700}
button:hover{background:#3d3b37} button:focus-visible,input:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid #6b8bbf;outline-offset:2px}
.subrow{display:flex;flex-wrap:wrap;justify-content:space-between;gap:14px;align-items:end}.subrow>div{flex:1;min-width:190px}
small{font-size:12px;color:#65635f}.status{padding:4px 10px;border-radius:30px;background:#f1ede6;font-size:12px;font-weight:700;display:inline-block}
.find{border-top:1px solid #e6e4df;padding:19px 0}.find h3{font-size:17px;margin:7px 0}.find p{line-height:1.55;margin:7px 0}.simple{background:#f7f5f1;padding:12px;border-radius:9px}
.sev{font-size:11px;font-weight:800;letter-spacing:.02em;display:inline-block;margin-right:7px}.sev.HIGH,.sev.CRITICAL{color:#a32f2a}.sev.MEDIUM{color:#916218}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.mini{background:#f7f6f3;border-radius:10px;padding:12px}.mini b{display:block}
.notice{border-left:3px solid #928a7c;padding:8px 13px;background:#f8f7f4;line-height:1.5}
footer{margin-top:35px;font-size:12px;color:#6a6761}
"""


def esc(v: object) -> str:
    return html.escape(str(v), quote=True)


def render_report(report: dict | None) -> str:
    if not report:
        return ""
    checks = report.get("checks", [])
    findings = report.get("findings", [])
    basic = report.get("profile") == "basic"
    if basic:
        state = "Basic checks finished. This is not a complete security review."
    elif report["gate"]["passed"]:
        state = "Configured checks completed without a high-severity blocker. More testing is still needed."
    else:
        state = "Needs attention: serious findings or incomplete checks."
    out = ["<section class='panel' aria-live='polite'><h2>Your results</h2>",
           f"<p class='notice'><strong>{esc(state)}</strong></p>",
           f"<p>{len(findings)} findings. <span class='muted'>Secrets are never displayed in the report.</span></p>",
           "<h3>What was actually checked</h3><div class='cols'>"]
    for c in checks:
        description = c.get("reason") or ("The scanner ran and its report was parsed." if c["status"] == "complete" else "Unable to check this area.")
        out.append(f"<div class='mini'><b>{esc(c['engine'])}</b><span class='status'>{esc(c['status'])}</span><p><small>{esc(description)}</small></p></div>")
    out.append("</div><h3>Things to look at</h3>")
    if not findings:
        out.append("<p>No findings in checks that completed. That does not prove the app is secure.</p>")
    for item in findings[:100]:
        line = f":{item['line']}" if item.get("line") else ""
        out.append(f"<article class='find'><span class='sev {esc(item['severity'])}'>{esc(item['severity'])}</span>"
                   f"<small>{esc(item['engine'])} · {esc(item['path'])}{esc(line)}</small>"
                   f"<h3>{esc(item['title'])}</h3>")
        if item.get("simple_explanation"):
            out.append(f"<p class='simple'><strong>In everyday words:</strong> {esc(item['simple_explanation'])}</p>")
        if item.get("suggested_action"):
            out.append(f"<p><strong>What to do:</strong> {esc(item['suggested_action'])}</p>")
        if item.get("reference"):
            reference = item["reference"]
            if isinstance(reference, str) and reference.startswith(("https://osv.dev/", "https://github.com/advisories/", "https://react.dev/")):
                out.append(f"<p><a href='{esc(reference)}' target='_blank' rel='noopener noreferrer'>Read official advisory ↗</a></p>")
        out.append("</article>")
    if len(findings) > 100:
        out.append("<p>Only the first 100 findings are shown here. Use the JSON report for the full list.</p>")
    out.append("<p><a href='/report.json'>Get the full technical JSON report</a></p></section>")
    return "".join(out)


def render_page(token: str, workspace: str, profile: str, report: dict | None, message: str = "") -> bytes:
    choices = "".join(f"<option value='{x}'{' selected' if x == profile else ''}>{y}</option>" for x, y in (
        ("basic", "Basic: quick local checks"),
        ("quick", "Developer: add code, secret and dependency scanners"),
        ("full", "Full: also check Docker and configuration")))
    cases = bundled_data("incidents.json")["incidents"]
    news = "".join(f"<div class='mini'><b>{esc(i['title'])}</b><p>{esc(i['plain_english'])}</p>"
                   f"<small>Defense: {esc(i['technical_lesson'])}</small></div>" for i in cases)
    policies = bundled_data("policies.json")
    policy_cards = "".join(
        "<div class='mini'><b>" + esc(p["title"]) + "</b>"
        "<p>" + esc(p["simple"]) + "</p>"
        "<small>" + esc(p["platform"].upper()) + " · Human review needed · "
        + " · ".join(esc(v) for v in p["evidence"][:2])
        + "</small><p><a href='" + esc(p["source"]) + "' target='_blank' rel='noopener noreferrer'>Official policy ↗</a></p></div>"
        for p in policies["policies"]
    )
    intel = kev_status()
    page = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
    <meta name='referrer' content='no-referrer'><title>DefenTail | Understand and protect your app</title>
    <style>{STYLE}</style></head><body><main class='wrap'>
    <header><span class='logo'>◆ DEFENTAIL <small>by Syrava</small></span><span class='status'>Private on this computer</span></header>
    <h1 class='hero'>Build things.<br>Know what needs fixing.</h1>
    <p class='lead'>Like a friendly safety inspector for your app. Choose a project folder, ask it to check, and see what each problem means in plain English.</p>
    <section class='panel'><h2>Check your app</h2><form method='post' action='/scan'>
    <input type='hidden' name='token' value='{esc(token)}'>
    <label for='workspace'>Project folder</label><input id='workspace' name='workspace' value='{esc(workspace)}' spellcheck='false' required>
    <small>On Windows, open File Explorer, click the folder address bar, then copy the folder path here.</small>
    <div class='subrow'><div><label for='profile'>How much should I check?</label><select id='profile' name='profile'>{choices}</select></div>
    <button type='submit'>Check my app →</button></div>
    <p><small><strong>Privacy:</strong> Basic stays on this computer. Advanced scanners run locally, but dependency and database scanners may access online advisory services. DefenTail itself does not upload your source code.</small></p></form></section>
    {"<p class='notice' role='alert'>" + esc(message) + "</p>" if message else ''}
    {render_report(report)}
    <section class='panel'><h2>What past incidents taught us</h2><p class='muted'>Sourced lessons, not news headlines passed off as proof.</p><div class='cols'>{news}</div>
    <p><small>CISA known-exploited vulnerability feed: {esc(intel.get('status'))}. Update it explicitly with <code>defentail update-intel</code>.</small></p></section>
    <section class='panel'><h2>Store rules and privacy checks</h2>
      <p class='muted'>Small steps to help your app follow store rules. These need real people to verify them. No automatic approval promise.</p>
      <div class='cols'>{policy_cards}</div>
      <p><small>Checklist reviewed as of {esc(policies['as_of'])}. You can compare official policy changes with <code>defentail check-policies</code>.</small></p></section>
    <footer>MIT-licensed DefenTail prototype. Neither scanners nor checklists guarantee safety, app-store approval, or legal compliance.</footer></main></body></html>"""
    return page.encode("utf-8")


def serve(workspace: Path, port: int = 0, launch: bool = True) -> None:
    csrf = secrets.token_urlsafe(28)
    state = {"root": str(workspace.resolve()), "profile": "basic", "report": None, "message": ""}

    class Handler(BaseHTTPRequestHandler):
        def _write(self, body: bytes, ctype: str, status: int = 200) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _valid_host(self) -> bool:
            host = self.headers.get("Host", "")
            return host in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}")

        def do_GET(self) -> None:
            if not self._valid_host():
                return self._write(b"Bad Host", "text/plain", 403)
            if self.path == "/":
                return self._write(render_page(csrf, state["root"], state["profile"],
                                               state["report"], state["message"]), "text/html; charset=utf-8")
            if self.path == "/report.json" and state["report"] is not None:
                return self._write(json.dumps(state["report"], indent=2).encode(), "application/json")
            return self._write(b"Not found", "text/plain", 404)

        def do_POST(self) -> None:
            if not self._valid_host() or self.path != "/scan":
                return self._write(b"Forbidden", "text/plain", 403)
            origin = self.headers.get("Origin", "")
            if origin and origin not in (f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"):
                return self._write(b"Wrong origin", "text/plain", 403)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 12_000:
                    raise ValueError("Request too large")
                post = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
                if not secrets.compare_digest(post.get("token", [""])[0], csrf):
                    return self._write(b"CSRF check failed", "text/plain", 403)
                root = Path(post.get("workspace", [""])[0]).expanduser().resolve(strict=True)
                profile = post.get("profile", ["basic"])[0]
                if not root.is_dir() or profile not in ("basic", "quick", "full"):
                    raise ValueError("Choose an existing project folder and a valid check level")
                state["root"], state["profile"] = str(root), profile
                state["report"] = scan(root, profile=profile, timeout=120)
                state["message"] = ""
            except (ValueError, OSError, UnicodeError) as exc:
                state["message"] = f"Couldn't complete this check: {str(exc)[:180]}"
            return self._write(render_page(csrf, state["root"], state["profile"], state["report"],
                                           state["message"]), "text/html; charset=utf-8")

        def log_message(self, *_args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"DefenTail browser UI: {url}\nFor privacy, it only listens on this computer. Press Ctrl+C to stop.")
    if launch:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
