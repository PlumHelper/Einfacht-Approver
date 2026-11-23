"""Per-repo isolated webhook aggregator & dispatcher (zero cross-repo mixing)."""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def read_webhook_routes(path: Path) -> list[tuple[str, str]]:
    """Parse `<repo_or_star> <url>` or bare `<url>` lines from `path`."""
    if not path.is_file():
        return []
    try:
        raw = path.read_text("utf-8")
    except OSError:
        return []
    routes: list[tuple[str, str]] = []
    for ln in raw.splitlines():
        line = ln.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].startswith(("http://", "https://")):
            routes.append((parts[0], parts[1].strip()))
        elif line.startswith(("http://", "https://")):
            routes.append(("*", line))
    return routes


def urls_for_repo(repo: str, path: Path) -> list[str]:
    """Return deduplicated webhook URLs matching `repo` (exact match or `*`)."""
    seen: list[str] = []
    for pat, url in read_webhook_routes(path):
        if (pat == "*" or pat == repo) and url not in seen:
            seen.append(url)
    return seen


def _post_json(url: str, payload: dict[str, Any], timeout: float = 10.0) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Einfacht-Approver/2.0"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=timeout).read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        sys.stderr.write(f"webhook_error({url}): {exc}\n")


class RepoWebhookDispatcher:
    """Per-repo bucketed webhook aggregator: RepoA events never mix with RepoB."""

    def __init__(self, request_webhook_file: Path, decision_webhook_file: Path,
                 debounce_sec: float = 0.5):
        self.request_webhook_file = Path(request_webhook_file)
        self.decision_webhook_file = Path(decision_webhook_file)
        self.debounce_sec = debounce_sec
        self._lock = threading.Lock()
        self._req_batches: dict[str, list[dict[str, Any]]] = {}
        self._req_timers: dict[str, threading.Timer] = {}
        self._dec_batches: dict[str, list[dict[str, Any]]] = {}
        self._dec_timers: dict[str, threading.Timer] = {}

    def notify_request(self, req: dict[str, Any]) -> None:
        repo = str(req.get("repo") or "*")
        if not urls_for_repo(repo, self.request_webhook_file):
            return
        with self._lock:
            self._req_batches.setdefault(repo, []).append(req)
            if repo not in self._req_timers:
                t = threading.Timer(self.debounce_sec, self._flush_request_repo, args=(repo,))
                t.daemon = True
                self._req_timers[repo] = t
                t.start()

    def _flush_request_repo(self, repo: str) -> None:
        with self._lock:
            batch = self._req_batches.pop(repo, [])
            self._req_timers.pop(repo, None)
        if not batch:
            return
        hooks = urls_for_repo(repo, self.request_webhook_file)
        if not hooks:
            return
        first = batch[0]
        payload = {
            "event": "approval.requested",
            "repo": repo,
            "count": len(batch),
            "req_id": first["id"],
            "display_id": first.get("display_id", first["id"]),
            "display_ids": [r.get("display_id", r["id"]) for r in batch],
            "action": first["action"],
            "target_path": first["target_path"],
        }
        for url in hooks:
            _post_json(url, payload)

    def notify_decision(self, req: dict[str, Any]) -> None:
        repo = str(req.get("repo") or "*")
        if not urls_for_repo(repo, self.decision_webhook_file):
            return
        with self._lock:
            self._dec_batches.setdefault(repo, []).append(req)
            if repo not in self._dec_timers:
                t = threading.Timer(self.debounce_sec, self._flush_decision_repo, args=(repo,))
                t.daemon = True
                self._dec_timers[repo] = t
                t.start()

    def _flush_decision_repo(self, repo: str) -> None:
        with self._lock:
            batch = self._dec_batches.pop(repo, [])
            self._dec_timers.pop(repo, None)
        if not batch:
            return
        hooks = urls_for_repo(repo, self.decision_webhook_file)
        if not hooks:
            return
        approved = [r.get("display_id", r["id"]) for r in batch if str(r.get("status", "")).startswith("approved")]
        denied = [r.get("display_id", r["id"]) for r in batch if r.get("status") == "denied"]
        payload = {
            "event": "approval.decided",
            "repo": repo,
            "count": len(batch),
            "approved": approved,
            "denied": denied,
            "decided_by": batch[-1].get("decided_by", "admin"),
            "summary": f"{len(approved)} approved, {len(denied)} denied",
        }
        for url in hooks:
            _post_json(url, payload)

    def flush_all(self) -> None:
        """Immediately flush all pending per-repo batches and wait for in-flight sends."""
        with self._lock:
            timers = list(self._req_timers.values()) + list(self._dec_timers.values())
            for t in timers:
                t.cancel()
            req_repos = list(self._req_batches.keys())
            dec_repos = list(self._dec_batches.keys())
        for t in timers:
            t.join(timeout=1.0)
        for repo in req_repos:
            self._flush_request_repo(repo)
        for repo in dec_repos:
            self._flush_decision_repo(repo)
