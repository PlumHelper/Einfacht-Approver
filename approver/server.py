"""ThreadingHTTPServer implementing Approver Protocol v2 and RBAC-scoped Web UI."""
from __future__ import annotations

import html
import http.cookies
import http.server
import json
import urllib.parse
from typing import Any

from .store import ApproverStore, ForbiddenError, SuiteSeqConflictError
from .webhooks import RepoWebhookDispatcher


def _render_login(error: str = "") -> str:
    err_html = f"<p style='color:#c00'>{html.escape(error)}</p>" if error else ""
    return (
        "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Einfacht Approver Login</title></head>"
        "<body style='font-family:sans-serif;max-width:480px;margin:40px auto;padding:0 16px'>"
        "<h2>Einfacht Isolated Approver v2</h2>"
        f"{err_html}"
        "<form method='post' action='/login'>"
        "<label>Approver Passphrase:<br>"
        "<input type='password' name='passphrase' style='width:100%;padding:8px;margin:8px 0'></label><br>"
        "<button type='submit' style='padding:10px 16px'>Sign in</button>"
        "</form></body></html>"
    )


def _parse_repos_field(raw_val: Any) -> list[str]:
    if isinstance(raw_val, list):
        return [str(x).strip() for x in raw_val if str(x).strip()]
    import re
    return [x.strip() for x in re.split(r"[\s,]+", str(raw_val or "")) if x.strip()]


def _render_keychains_section(store: ApproverStore, allowed_repos: frozenset[str],
                              banner: str = "") -> str:
    if "*" not in allowed_repos:
        return ""
    keychains = store.list_all_keychains()
    tokens = store.list_thread_tokens(allowed_repos)
    kc_rows = []
    for tid in sorted(set(keychains) | set(tokens)):
        repos = keychains.get(tid, [])
        tok = tokens.get(tid, "")
        chips = " ".join(
            f"<form method='post' action='/keychain/unbind' style='display:inline;margin-right:6px'>"
            f"<input type='hidden' name='approver' value='{html.escape(tid)}'>"
            f"<input type='hidden' name='repo' value='{html.escape(r)}'>"
            f"<code>{html.escape(r)}</code> <button type='submit' style='font-size:11px'>×</button></form>"
            for r in repos
        ) or "<span style='color:#888;font-size:12px'>(no repos bound)</span>"
        if tok:
            tok_html = (
                f"<div style='margin-top:4px;font-size:12px'>"
                f"Token: <code style='background:#f3f3f3;padding:2px 6px;border-radius:4px;user-select:all'>{html.escape(tok)}</code> "
                f"<button type='button' data-copy='{html.escape(tok)}' onclick='efCopy(this)' "
                f"style='font-size:11px;padding:2px 8px;cursor:pointer'>Copy Token</button> "
                f"<form method='post' action='/keychain' style='display:inline;margin-left:4px'>"
                f"<input type='hidden' name='approver' value='{html.escape(tid)}'>"
                f"<input type='hidden' name='issue_token' value='1'>"
                f"<button type='submit' style='font-size:11px;padding:2px 6px'>Rotate Token</button></form>"
                f"</div>"
            )
        else:
            tok_html = (
                f"<div style='margin-top:4px;font-size:12px;color:#777'>"
                f"Token: <span>(not stored / legacy hash)</span> "
                f"<form method='post' action='/keychain' style='display:inline;margin-left:4px'>"
                f"<input type='hidden' name='approver' value='{html.escape(tid)}'>"
                f"<input type='hidden' name='issue_token' value='1'>"
                f"<button type='submit' style='font-size:11px;padding:2px 6px'>Generate Token</button></form>"
                f"</div>"
            )
        kc_rows.append(
            f"<li style='margin-bottom:10px'><b><code>{html.escape(tid)}</code></b>: {chips}{tok_html}</li>"
        )
    banner_html = (
        f"<div style='background:#eef7ee;border:1px solid #4a8;padding:10px;border-radius:6px;margin:10px 0'>{banner}</div>"
        if banner else ""
    )
    return (
        "<h3>Thread Keychains (Bind Many Repos &amp; Issue Token — Admin Only)</h3>"
        f"{banner_html}"
        "<form method='post' action='/keychain' style='border:1px solid #ccc;padding:12px;border-radius:8px;margin-bottom:12px'>"
        "<div style='margin-bottom:8px'><label>Thread ID:<br>"
        "<input name='approver' placeholder='T3CODE_THREAD_ID' style='width:100%;padding:6px'></label></div>"
        "<div style='margin-bottom:8px'><label>Repos (comma / space / newline separated):<br>"
        "<textarea name='repos' rows='3' placeholder='ArchivalEra/Einfacht, org/repo-01, org/repo-02' style='width:100%;padding:6px'></textarea></label></div>"
        "<label><input type='checkbox' name='issue_token' value='1' checked> Issue / rotate thread token (saved for admin copy anytime)</label><br><br>"
        "<button type='submit' style='padding:8px 14px'>Bind Repos &amp; Issue Token</button>"
        "</form>"
        f"<ul>{''.join(kc_rows) or '<li>No thread keychains bound yet.</li>'}</ul>"
    )


def _render_dashboard(store: ApproverStore, allowed_repos: frozenset[str], approver: str,
                      banner: str = "") -> str:
    pending = store.list_requests(allowed_repos, status="pending", limit=200)
    delegs, revoked = store.list_delegations(allowed_repos)
    rev_set = set(revoked)
    cards = []
    for r in pending:
        suite_line = f" · seq: <code>{r['suite_seq']}</code>" if r.get("suite_seq") is not None else ""
        deleg_btn = (
            "" if r["action"] == "suite.release"
            else f"<button name='mode' value='delegate_30m' style='padding:8px 12px'>Delegate 30m ({html.escape(r['action'])})</button>"
        )
        cards.append(
            f"<div style='border:1px solid #999;border-radius:8px;padding:12px;margin:12px 0'>"
            f"<div><b>{html.escape(r.get('display_id', r['id']))}</b> · Action: <code>{html.escape(r['action'])}</code>{suite_line}</div>"
            f"<div>Repo: <code>{html.escape(r['repo'])}</code> · Agent: <code>{html.escape(r['agent_id'])}</code></div>"
            f"<div>File: <code>{html.escape(r['target_path'])}</code></div>"
            f"<div style='font-size:12px;color:#555'>prev: <code>{html.escape(r['prev_sha256'][:16])}</code> → target: <code>{html.escape(r['target_sha256'][:16])}</code></div>"
            f"<pre style='background:#f6f6f6;padding:8px;overflow:auto'>{html.escape(r['diff_summary'])}</pre>"
            f"<form method='post' action='/approve' style='display:flex;gap:8px;flex-wrap:wrap'>"
            f"<input type='hidden' name='req_id' value='{html.escape(r['id'])}'>"
            f"<button name='mode' value='single' style='padding:8px 12px'>Approve Once</button>"
            f"{deleg_btn}"
            f"<input type='text' name='deny_reason' placeholder='Deny reason' style='padding:6px;flex:1;min-width:180px'>"
            f"<button name='mode' value='deny' style='padding:8px 12px;color:#b00'>Deny</button>"
            f"</form></div>"
        )
    deleg_rows = [
        f"<li><code>{html.escape(d['id'])}</code> · {html.escape(d['repo'])} · {html.escape(d['action'])}"
        + (" <b>[REVOKED]</b>" if d["id"] in rev_set else
           f" <form method='post' action='/revoke' style='display:inline'>"
           f"<input type='hidden' name='id' value='{html.escape(d['id'])}'>"
           f"<button type='submit'>Revoke</button></form>")
        + "</li>"
        for d in delegs
    ]
    return (
        "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Einfacht Approver v2</title></head>"
        "<body style='font-family:sans-serif;max-width:760px;margin:24px auto;padding:0 16px'>"
        "<div style='display:flex;justify-content:space-between;align-items:center'>"
        f"<h2>Einfacht Approver v2</h2>"
        "<form method='post' action='/logout'><button type='submit'>Sign out</button></form></div>"
        f"<p style='color:#555'>Approver: <b>{html.escape(approver)}</b> · Repos: <code>{html.escape(', '.join(sorted(allowed_repos)))}</code></p>"
        f"<h3>Pending Requests ({len(cards)})</h3>"
        f"{''.join(cards) or '<p>No pending requests.</p>'}"
        f"<h3>Active Delegations ({len(deleg_rows)})</h3>"
        f"<ul>{''.join(deleg_rows) or '<li>None</li>'}</ul>"
        f"{_render_keychains_section(store, allowed_repos, banner)}"
        "<script>"
        "if('scrollRestoration' in history){history.scrollRestoration='manual';}"
        "function efCopy(btn){"
        "var t=btn.getAttribute('data-copy')||'';"
        "var done=function(){var o=btn.textContent;btn.textContent='Copied!';setTimeout(function(){btn.textContent=o;},1200);};"
        "if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done).catch(function(){efFallbackCopy(t,done);});}"
        "else{efFallbackCopy(t,done);}"
        "}"
        "function efFallbackCopy(t,done){"
        "var ta=document.createElement('textarea');ta.value=t;ta.style.position='fixed';ta.style.opacity='0';"
        "document.body.appendChild(ta);ta.select();try{document.execCommand('copy');}catch(e){}document.body.removeChild(ta);done();"
        "}"
        "document.addEventListener('submit',function(e){"
        "var f=e.target;if(!f||f.tagName!=='FORM')return;"
        "var act=f.getAttribute('action')||'';"
        "if(act==='/logout'||act==='/login')return;"
        "e.preventDefault();"
        "var x=window.scrollX,y=window.scrollY;"
        "var fd=new FormData(f);"
        "if(e.submitter&&e.submitter.name){fd.set(e.submitter.name,e.submitter.value||'');}"
        "var body=new URLSearchParams();fd.forEach(function(v,k){body.append(k,v);});"
        "fetch(act,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString(),credentials:'same-origin'})"
        ".then(function(r){return r.text();})"
        ".then(function(h){"
        "var doc=new DOMParser().parseFromString(h,'text/html');"
        "if(doc&&doc.body){document.body.innerHTML=doc.body.innerHTML;history.replaceState(null,'','/');window.scrollTo(x,y);}"
        "});"
        "});"
        "</script>"
        "</body></html>"
    )


def make_handler(store: ApproverStore, dispatcher: RepoWebhookDispatcher) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _json(self, code: int, obj: Any) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, code: int, body_str: str, cookie: str | None = None) -> None:
            body = body_str.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def _redirect(self, location: str, cookie: str | None = None) -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()

        def _session_id(self) -> str | None:
            raw = self.headers.get("Cookie", "")
            c = http.cookies.SimpleCookie()
            try:
                c.load(raw)
            except http.cookies.CookieError:
                return None
            return c["approver_sess"].value if "approver_sess" in c else None

        def _current_identity(self) -> tuple[str, frozenset[str]] | None:
            auth = self.headers.get("Authorization") or ""
            if auth.startswith("Bearer "):
                ident = store.bearer_identity(auth[7:].strip())
                if ident:
                    return ident
            pw = (self.headers.get("X-Approver-Pass") or "").strip()
            if pw:
                ident = store.verify_approver(pw) or store.bearer_identity(pw)
                if ident:
                    return ident
            return store.session_identity(self._session_id())

        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path == "/":
                ident = self._current_identity()
                if not ident:
                    self._html(200, _render_login())
                    return
                self._html(200, _render_dashboard(store, ident[1], ident[0]))
                return
            if path == "/pubkey":
                pub_pem, kid = store.key_info()
                self._json(200, {"public_key_pem": pub_pem, "key_id": kid})
                return
            if path == "/revocations":
                self._json(200, {"revoked": store.list_revocations()})
                return
            if path.startswith("/requests/"):
                key = urllib.parse.unquote(path.split("/", 2)[2])
                req = store.get_request(key)
                self._json(200 if req else 404, req or {"error": "not_found"})
                return
            if path in ("/api/requests", "/api/pending"):
                ident = self._current_identity()
                if not ident:
                    self._json(403, {"error": "forbidden"})
                    return
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                status = qs.get("status", ["pending" if path == "/api/pending" else ""])[0] or None
                items = store.list_requests(ident[1], status=status)
                self._json(200, {"approver": ident[0], "allowed_repos": sorted(ident[1]), "requests": items, "pending": items})
                return
            if path == "/api/delegations":
                ident = self._current_identity()
                if not ident:
                    self._json(403, {"error": "forbidden"})
                    return
                delegs, rev = store.list_delegations(ident[1])
                self._json(200, {"approver": ident[0], "allowed_repos": sorted(ident[1]), "delegations": delegs, "revoked": rev})
                return
            self._json(404, {"error": "not_found"})

        def _read_body(self) -> str | None:
            raw_len = self.headers.get("Content-Length", "0") or "0"
            try:
                n = int(raw_len)
            except ValueError:
                self._json(400, {"error": "bad_content_length"})
                return None
            if n < 0:
                self._json(400, {"error": "bad_content_length"})
                return None
            if n > 1_048_576:
                self._json(413, {"error": "payload_too_large"})
                return None
            return self.rfile.read(n).decode("utf-8", errors="replace") if n > 0 else ""

        def _parse_json_or_form(self, raw: str) -> dict[str, Any]:
            ctype = self.headers.get("Content-Type", "")
            if "application/json" in ctype:
                try:
                    data = json.loads(raw or "{}")
                    return data if isinstance(data, dict) else {}
                except ValueError:
                    return {}
            parsed = urllib.parse.parse_qs(raw)
            return {k: v[0] for k, v in parsed.items() if v}

        def do_POST(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            raw = self._read_body()
            if raw is None:
                return
            if path == "/requests":
                try:
                    body = json.loads(raw or "{}")
                except ValueError:
                    self._json(400, {"error": "bad_json"})
                    return
                if not isinstance(body, dict) or not all(body.get(k) for k in ("repo", "action", "target_path", "target_sha256")):
                    self._json(400, {"error": "missing_fields"})
                    return
                try:
                    req, is_new = store.submit_request(body)
                except ValueError as exc:
                    self._json(400, {"error": "bad_request", "detail": str(exc)})
                    return
                except SuiteSeqConflictError as exc:
                    self._json(409, {"error": "suite_seq_conflict", "detail": str(exc)})
                    return
                if is_new:
                    dispatcher.notify_request(req)
                self._json(201 if is_new else 200, req)
                return

            if path == "/login":
                data = self._parse_json_or_form(raw)
                secret_val = str(data.get("passphrase") or "").strip()
                pw_ident = store.verify_approver(secret_val)
                if pw_ident:
                    tok = store.create_session(pw_ident[0], pw_ident[1])
                else:
                    tok_ident = store.bearer_identity(secret_val)
                    if not tok_ident:
                        self._html(401, _render_login("Invalid passphrase"))
                        return
                    tok = store.create_session(tok_ident[0], frozenset())
                self._redirect("/", cookie=f"approver_sess={tok}; HttpOnly; SameSite=Lax; Path=/")
                return

            if path == "/logout":
                sess_tok = self._session_id()
                if sess_tok:
                    store.delete_session(sess_tok)
                self._redirect("/", cookie="approver_sess=; Max-Age=0; Path=/")
                return

            if path in ("/api/keychain/bind", "/keychain"):
                ident = self._current_identity()
                if not ident or "*" not in ident[1]:
                    self._json(403, {"error": "forbidden"})
                    return
                data = self._parse_json_or_form(raw)
                ap_name = str(data.get("approver") or "").strip()
                repos_list = _parse_repos_field(data.get("repos") if data.get("repos") is not None else data.get("repo"))
                if not ap_name or (not repos_list and not data.get("issue_token")):
                    self._json(400, {"error": "missing_fields"})
                    return
                bound = store.bind_keychain_many(ap_name, repos_list)
                issued_tok = store.issue_thread_token(ap_name) if data.get("issue_token") else None
                if path == "/keychain":
                    msg = f"Bound <code>{html.escape(ap_name)}</code> → <code>{html.escape(', '.join(bound or ['(unchanged)']))}</code>"
                    if issued_tok:
                        msg += f"<br>Token (copy into <code>request_secret</code>): <code>{html.escape(issued_tok)}</code>"
                    self._html(200, _render_dashboard(store, ident[1], ident[0], banner=msg))
                    return
                out: dict[str, Any] = {"approver": ap_name, "repos": bound, "bound": True}
                if issued_tok:
                    out["token"] = issued_tok
                self._json(200, out)
                return

            if path in ("/api/keychain/unbind", "/keychain/unbind"):
                ident = self._current_identity()
                if not ident or "*" not in ident[1]:
                    self._json(403, {"error": "forbidden"})
                    return
                data = self._parse_json_or_form(raw)
                ap_name = str(data.get("approver") or "").strip()
                repo_name = str(data.get("repo") or "").strip()
                if not ap_name or not repo_name:
                    self._json(400, {"error": "missing_fields"})
                    return
                store.unbind_keychain(ap_name, repo_name)
                if path == "/keychain/unbind":
                    self._redirect("/")
                else:
                    self._json(200, {"approver": ap_name, "repo": repo_name, "unbound": True})
                return

            if path in ("/api/decide", "/approve"):
                ident = self._current_identity()
                if not ident:
                    self._json(403, {"error": "forbidden"})
                    return
                data = self._parse_json_or_form(raw)
                req_id = str(data.get("req_id") or "")
                mode = str(data.get("mode") or "single")
                deny_reason = str(data.get("deny_reason") or "")
                try:
                    updated = store.decide_request(
                        req_id, mode, approver=ident[0], allowed_repos=ident[1], deny_reason=deny_reason)
                except ValueError as exc:
                    self._json(400, {"error": "bad_mode", "detail": str(exc)})
                    return
                except ForbiddenError as exc:
                    self._json(403, {"error": "forbidden", "detail": str(exc)})
                    return
                except SuiteSeqConflictError as exc:
                    self._json(409, {"error": "suite_seq_conflict", "detail": str(exc)})
                    return
                if updated is None:
                    self._json(404, {"error": "not_found"})
                    return
                dispatcher.notify_decision(updated)
                if path == "/approve":
                    self._redirect("/")
                else:
                    self._json(200, updated)
                return

            if path in ("/api/revoke", "/revoke"):
                ident = self._current_identity()
                if not ident:
                    self._json(403, {"error": "forbidden"})
                    return
                data = self._parse_json_or_form(raw)
                target_id = str(data.get("id") or "")
                try:
                    store.revoke_id(target_id, allowed_repos=ident[1])
                except ForbiddenError as exc:
                    self._json(403, {"error": "forbidden", "detail": str(exc)})
                    return
                if path == "/revoke":
                    self._redirect("/")
                else:
                    self._json(200, {"revoked": target_id})
                return

            self._json(404, {"error": "not_found"})

    return Handler


def create_server(host: str, port: int, store: ApproverStore,
                  dispatcher: RepoWebhookDispatcher) -> http.server.ThreadingHTTPServer:
    """Create a `ThreadingHTTPServer` bound to `(host, port)`."""
    return http.server.ThreadingHTTPServer((host, port), make_handler(store, dispatcher))
