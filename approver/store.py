"""SQLite WAL-backed store with composite indexes, RBAC, and atomic suite_seq concurrency control."""
from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import crypto

_SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    display_id TEXT NOT NULL,
    repo TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_path TEXT NOT NULL,
    prev_sha256 TEXT NOT NULL,
    target_sha256 TEXT NOT NULL,
    diff_summary TEXT NOT NULL,
    target_content TEXT NOT NULL,
    suite_seq INTEGER,
    status TEXT NOT NULL,
    deny_reason TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL DEFAULT '',
    receipt_json TEXT,
    created_at INTEGER NOT NULL,
    decided_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_req_dedup
    ON requests(repo, action, target_path, prev_sha256, target_sha256, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_req_repo_status
    ON requests(repo, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_req_display
    ON requests(display_id);

CREATE TABLE IF NOT EXISTS delegations (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    action TEXT NOT NULL,
    approver TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deleg_lookup
    ON delegations(repo, action, expires_at DESC);

CREATE TABLE IF NOT EXISTS revocations (
    id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    approver TEXT NOT NULL,
    repos_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS repo_counters (
    repo TEXT PRIMARY KEY,
    last_seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS suite_releases (
    upstream_repo TEXT PRIMARY KEY,
    last_seq INTEGER NOT NULL,
    tree_sha256 TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS approver_keychains (
    approver TEXT NOT NULL,
    repo TEXT NOT NULL,
    bound_at INTEGER NOT NULL,
    PRIMARY KEY (approver, repo)
);

CREATE TABLE IF NOT EXISTS thread_tokens (
    token_hash TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    token_plain TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
"""


def can_access_repo(allowed_repos: frozenset[str], repo: str) -> bool:
    """True iff `allowed_repos` grants access to `repo` (`*` or exact match)."""
    return "*" in allowed_repos or repo in allowed_repos


SUITE_RELEASE_COMPAT_EXPIRES_AT = 4102444800  # 2100-01-01T00:00:00Z compat for un-upgraded v2 clients


class SuiteSeqConflictError(Exception):
    """Raised when a concurrent `suite.release` collides with or regresses `last_seq`."""


class ForbiddenError(Exception):
    """Raised when an approver lacks RBAC permission for the target repo/action."""


class ApproverStore:
    """Thread-safe SQLite WAL store for multi-repo Ed25519 approvals."""

    def __init__(self, state_dir: Path, pass_file: Path):
        self.state_dir = Path(state_dir)
        self.pass_file = Path(pass_file)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.chmod(0o700)
        self.db_path = self.state_dir / "approver.db"
        self.priv: Ed25519PrivateKey
        self.pub_pem_str: str
        self.key_id: str
        self.priv, self.pub_pem_str, self.key_id = crypto.load_or_create_keypair(self.state_dir)
        self._local = threading.local()
        self._conns: list[sqlite3.Connection] = []
        self._write_lock = threading.RLock()
        self._auth_cache_sig: tuple[int, int] | None = None
        self._auth_cache: dict[str, tuple[str, frozenset[str]] | None] = {}
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
            with self._write_lock:
                self._conns.append(conn)
        return conn

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """Serialize SQLite write transactions with guarded rollback."""
        with self._write_lock:
            c = self._conn()
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise

    def close(self) -> None:
        """Close all tracked SQLite connections."""
        with self._write_lock:
            for conn in self._conns:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
            self._conns.clear()
            self._local.conn = None

    def _init_db(self) -> None:
        with self._write_lock:
            c = self._conn()
            c.executescript(_SCHEMA_SQL)
            with contextlib.suppress(sqlite3.OperationalError):
                c.execute("ALTER TABLE thread_tokens ADD COLUMN token_plain TEXT NOT NULL DEFAULT ''")
            if self.db_path.is_file():
                self.db_path.chmod(0o600)

    def close_thread_conn(self) -> None:
        """Close thread-local SQLite connection if open."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            with self._write_lock:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
                if conn in self._conns:
                    self._conns.remove(conn)
            self._local.conn = None

    def key_info(self) -> tuple[str, str]:
        return self.pub_pem_str, self.key_id

    def bind_keychain_many(self, approver: str, repos: list[str] | tuple[str, ...],
                           *, allowed_repos: frozenset[str] | None = None) -> list[str]:
        """Bind multiple `repos` to `approver`'s keychain in one transaction."""
        if allowed_repos is not None and "*" not in allowed_repos:
            raise ForbiddenError("only wildcard owner can modify keychains")
        cleaned = sorted({r.strip() for r in repos if r and r.strip()})
        if not cleaned:
            return []
        now = int(time.time())
        with self._tx() as c:
            for repo in cleaned:
                c.execute(
                    "INSERT OR IGNORE INTO approver_keychains(approver, repo, bound_at) VALUES(?,?,?)",
                    (approver, repo, now),
                )
        return cleaned

    def unbind_keychain(self, approver: str, repo: str,
                        *, allowed_repos: frozenset[str] | None = None) -> None:
        """Remove `repo` from `approver`'s keychain."""
        if allowed_repos is not None and "*" not in allowed_repos:
            raise ForbiddenError("only wildcard owner can modify keychains")
        with self._write_lock:
            self._conn().execute(
                "DELETE FROM approver_keychains WHERE approver=? AND repo=?",
                (approver, repo),
            )

    def list_all_keychains(self) -> dict[str, list[str]]:
        """Return `{approver: [repo, ...]}` across all keychains."""
        rows = self._conn().execute(
            "SELECT approver, repo FROM approver_keychains ORDER BY approver, repo"
        ).fetchall()
        out: dict[str, list[str]] = {}
        for r in rows:
            out.setdefault(str(r["approver"]), []).append(str(r["repo"]))
        return out

    def issue_thread_token(self, thread_id: str,
                           *, allowed_repos: frozenset[str] | None = None) -> str:
        """Issue a bearer token bound directly to `thread_id` (zero keypair/challenge)."""
        if allowed_repos is not None and "*" not in allowed_repos:
            raise ForbiddenError("only wildcard owner can issue thread tokens")
        import hashlib
        import secrets
        tok = "ef-tok-" + secrets.token_urlsafe(24)
        tok_hash = hashlib.sha256(tok.encode("utf-8")).hexdigest()
        with self._tx() as c:
            c.execute("DELETE FROM thread_tokens WHERE thread_id=?", (thread_id,))
            c.execute(
                "INSERT INTO thread_tokens(token_hash, thread_id, token_plain, created_at) VALUES(?,?,?,?)",
                (tok_hash, thread_id, tok, int(time.time())),
            )
        return tok

    def list_thread_tokens(self, allowed_repos: frozenset[str]) -> dict[str, str]:
        """Return `{thread_id: token_plain}` strictly for wildcard admin (`*` in `allowed_repos`)."""
        if "*" not in allowed_repos:
            raise ForbiddenError("only wildcard admin can view thread tokens")
        rows = self._conn().execute(
            "SELECT thread_id, token_plain FROM thread_tokens ORDER BY thread_id"
        ).fetchall()
        return {str(r["thread_id"]): str(r["token_plain"] or "") for r in rows}

    def bearer_identity(self, token: str | None) -> tuple[str, frozenset[str]] | None:
        """Resolve a `thread_tokens` bearer token to `(thread_id, keychain_repos)`."""
        import hashlib
        clean = (token or "").strip()
        if not clean:
            return None
        tok_hash = hashlib.sha256(clean.encode("utf-8")).hexdigest()
        row = self._conn().execute(
            "SELECT thread_id FROM thread_tokens WHERE token_hash=?",
            (tok_hash,),
        ).fetchone()
        if row is not None:
            tid = str(row["thread_id"])
            return tid, self._effective_repos(tid, frozenset())
        return self.session_identity(clean)

    def _effective_repos(self, approver: str, static_repos: frozenset[str]) -> frozenset[str]:
        if "*" in static_repos:
            return static_repos
        rows = self._conn().execute(
            "SELECT repo FROM approver_keychains WHERE approver=?",
            (approver,),
        ).fetchall()
        kc = {str(r["repo"]) for r in rows}
        return static_repos | frozenset(kc)

    def verify_approver(self, passphrase: str) -> tuple[str, frozenset[str]] | None:
        import hashlib
        if not self.pass_file.is_file():
            return None
        try:
            st = self.pass_file.stat()
            sig = (st.st_mtime_ns, st.st_size)
            pw_key = hashlib.sha256(passphrase.encode("utf-8")).hexdigest()
            with self._write_lock:
                if self._auth_cache_sig != sig:
                    self._auth_cache.clear()
                    self._auth_cache_sig = sig
                if pw_key in self._auth_cache:
                    cached = self._auth_cache[pw_key]
                    if cached is None:
                        return None
                    return cached[0], self._effective_repos(cached[0], cached[1])
            raw = self.pass_file.read_text("utf-8")
        except OSError:
            return None
        ident = crypto.verify_passphrase(raw, passphrase)
        with self._write_lock:
            if self._auth_cache_sig == sig:
                self._auth_cache[pw_key] = ident
        if ident is None:
            return None
        return ident[0], self._effective_repos(ident[0], ident[1])

    def create_session(self, approver: str, repos: frozenset[str], ttl_sec: int = 86400) -> str:
        import secrets
        tok = secrets.token_urlsafe(32)
        exp = int(time.time()) + ttl_sec
        with self._tx() as c:
            c.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            c.execute(
                "INSERT INTO sessions(token, approver, repos_json, expires_at) VALUES(?,?,?,?)",
                (tok, approver, json.dumps(sorted(repos)), exp),
            )
        return tok

    def session_identity(self, token: str | None) -> tuple[str, frozenset[str]] | None:
        if not token:
            return None
        row = self._conn().execute(
            "SELECT approver, repos_json, expires_at FROM sessions WHERE token = ?",
            (token,),
        ).fetchone()
        if row is None or int(row["expires_at"]) <= int(time.time()):
            return None
        ap = str(row["approver"])
        return ap, self._effective_repos(ap, frozenset(json.loads(row["repos_json"])))

    def delete_session(self, token: str) -> None:
        with self._write_lock:
            self._conn().execute("DELETE FROM sessions WHERE token = ?", (token,))

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        raw_rec = d.pop("receipt_json", None)
        if raw_rec:
            d["receipt"] = json.loads(raw_rec)
        return d

    def _sign_req_receipt(self, req: dict[str, Any], *, decided_by: str,
                          delegation_id: str | None = None, ttl_sec: int = 3600) -> dict[str, Any]:
        now = int(time.time())
        exp = SUITE_RELEASE_COMPAT_EXPIRES_AT if req["action"] == "suite.release" else now + ttl_sec
        payload: dict[str, Any] = {
            "id": f"rec-{uuid.uuid4().hex[:12]}",
            "req_id": req["id"],
            "repo": req["repo"],
            "action": req["action"],
            "target": req["target_path"],
            "target_path": req["target_path"],
            "prev_sha256": req["prev_sha256"],
            "target_sha256": req["target_sha256"],
            "decided_by": decided_by,
            "issued_at": now,
            "expires_at": exp,
        }
        if req.get("suite_seq") is not None:
            payload["suite_seq"] = int(req["suite_seq"])
        if delegation_id:
            payload["delegation_id"] = delegation_id
        return crypto.sign_receipt(self.priv, payload)

    def submit_request(self, body: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Insert or deduplicate a request. Returns `(request_dict, is_new_pending)`."""
        repo = str(body.get("repo") or "").strip()
        action = str(body.get("action") or "").strip()
        target_path = str(body.get("target_path") or "").strip()
        prev_sha = str(body.get("prev_sha256") or "NONE")
        target_sha = str(body.get("target_sha256") or "")
        agent_id = str(body.get("agent_id") or "agent")
        diff_summary = str(body.get("diff_summary") or "")[:16000]
        target_content = str(body.get("target_content") or "")[:32000]
        raw_seq = body.get("suite_seq")
        if raw_seq is not None:
            if isinstance(raw_seq, (bool, float)):
                raise ValueError("invalid suite_seq")
            suite_seq: int | None = int(raw_seq)
        else:
            suite_seq = None
        now = int(time.time())
        key_fields = {
            "repo": repo, "action": action, "target_path": target_path,
            "prev": prev_sha, "target": target_sha,
        }

        with self._tx() as c:
            reused = self._reuse_existing_in_tx(c, key_fields, suite_seq, now)
            if reused is not None:
                return reused

            if action == "suite.release":
                if suite_seq is None or suite_seq <= 0:
                    raise SuiteSeqConflictError("suite_seq must be a positive integer")
                rel_row = c.execute(
                    "SELECT last_seq FROM suite_releases WHERE upstream_repo=?", (repo,),
                ).fetchone()
                if rel_row is not None and suite_seq <= int(rel_row["last_seq"]):
                    raise SuiteSeqConflictError(
                        f"suite_seq {suite_seq} <= last_released_seq {rel_row['last_seq']}"
                    )

            cnt_row = c.execute("SELECT last_seq FROM repo_counters WHERE repo=?", (repo,)).fetchone()
            next_num = (int(cnt_row["last_seq"]) if cnt_row else 0) + 1
            c.execute("INSERT OR REPLACE INTO repo_counters(repo, last_seq) VALUES(?,?)", (repo, next_num))
            req_id = f"req-{uuid.uuid4().hex[:12]}"
            display_id = f"{repo}#{next_num}"

            status, decided_by, decided_at, receipt = "pending", "", None, None
            if action != "suite.release":
                deleg = c.execute(
                    """SELECT d.* FROM delegations d
                       WHERE d.repo=? AND d.action=? AND d.expires_at > ?
                         AND d.id NOT IN (SELECT id FROM revocations)
                       ORDER BY d.expires_at DESC LIMIT 1""",
                    (repo, action, now),
                ).fetchone()
                if deleg is not None:
                    status, decided_by, decided_at = "approved_delegated", str(deleg["approver"]), now
                    receipt = self._sign_req_receipt(
                        {"id": req_id, "repo": repo, "action": action, "target_path": target_path,
                         "prev_sha256": prev_sha, "target_sha256": target_sha, "suite_seq": suite_seq},
                        decided_by=decided_by, delegation_id=str(deleg["id"]),
                    )

            c.execute(
                """INSERT INTO requests(
                       id, display_id, repo, agent_id, action, target_path,
                       prev_sha256, target_sha256, diff_summary, target_content,
                       suite_seq, status, deny_reason, decided_by, receipt_json,
                       created_at, decided_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (req_id, display_id, repo, agent_id, action, target_path,
                 prev_sha, target_sha, diff_summary, target_content,
                 suite_seq, status, "", decided_by,
                 json.dumps(receipt) if receipt else None, now, decided_at),
            )
            self._supersede_pending_in_tx(
                c, repo=repo, action=action, target_path=target_path,
                suite_seq=suite_seq, req_id=req_id, display_id=display_id, now=now,
            )
            row = c.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
            return self._row_to_dict(row), (status == "pending")

    def _reuse_existing_in_tx(self, c: sqlite3.Connection, body: dict[str, str],
                              suite_seq: int | None, now: int) -> tuple[dict[str, Any], bool] | None:
        existing = c.execute(
            """SELECT * FROM requests
               WHERE repo=? AND action=? AND target_path=? AND prev_sha256=? AND target_sha256=?
                 AND COALESCE(suite_seq, -1) = COALESCE(?, -1)
               ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (body["repo"], body["action"], body["target_path"], body["prev"], body["target"], suite_seq),
        ).fetchone()
        if existing is None:
            return None
        ex = self._row_to_dict(existing)
        if ex["status"] == "denied":
            return {**ex, "status": "rejected_duplicate", "original_id": ex["id"]}, False
        if ex["status"] == "pending":
            return ex, False
        if ex["status"] in ("approved", "approved_delegated"):
            ex_rec = ex.get("receipt") or {}
            exp_ts = self._parse_exp_ts(ex_rec.get("expires_at"))
            is_rev = c.execute(
                "SELECT 1 FROM revocations WHERE id IN (?,?)",
                (str(ex_rec.get("id") or ""), str(ex_rec.get("delegation_id") or "")),
            ).fetchone() is not None
            if not is_rev and exp_ts is not None and exp_ts > now:
                return ex, False
        return None

    def _supersede_pending_in_tx(self, c: sqlite3.Connection, *, repo: str, action: str,
                                 target_path: str, suite_seq: int | None, req_id: str,
                                 display_id: str, now: int) -> None:
        sup_reason = f"superseded by {display_id}"
        if action == "suite.release":
            c.execute(
                """UPDATE requests
                   SET status='superseded', deny_reason=?, decided_by='system:supersede', decided_at=?
                   WHERE repo=? AND action='suite.release' AND status='pending'
                     AND COALESCE(suite_seq, 0) < ? AND id != ?""",
                (sup_reason, now, repo, int(suite_seq or 0), req_id),
            )
            return
        c.execute(
            """UPDATE requests
               SET status='superseded', deny_reason=?, decided_by='system:supersede', decided_at=?
               WHERE repo=? AND action=? AND target_path=? AND status='pending' AND id != ?""",
            (sup_reason, now, repo, action, target_path, req_id),
        )

    def get_request(self, key: str) -> dict[str, Any] | None:
        c = self._conn()
        row = c.execute("SELECT * FROM requests WHERE id=?", (key,)).fetchone()
        if row is None:
            row = c.execute(
                "SELECT * FROM requests WHERE display_id=? ORDER BY created_at DESC LIMIT 1",
                (key,),
            ).fetchone()
        return self._row_to_dict(row) if row is not None else None

    def list_requests(self, allowed_repos: frozenset[str], status: str | None = None,
                      limit: int = 200) -> list[dict[str, Any]]:
        if not allowed_repos:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        if "*" not in allowed_repos:
            placeholders = ",".join("?" for _ in allowed_repos)
            clauses.append(f"repo IN ({placeholders})")
            params.extend(sorted(allowed_repos))
        if status:
            clauses.append("status=?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        params.append(limit)
        rows = self._conn().execute(
            f"SELECT * FROM requests {where}ORDER BY created_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def _decide_one_in_tx(self, c: sqlite3.Connection, req_id: str, mode: str, *, approver: str,
                          allowed_repos: frozenset[str], deny_reason: str, now: int) -> dict[str, Any] | None:
        if mode not in ("single", "delegate_30m", "deny"):
            raise ValueError(f"invalid decide mode: {mode!r}")
        row = c.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
        if row is None:
            return None
        req = self._row_to_dict(row)
        if not can_access_repo(allowed_repos, req["repo"]):
            raise ForbiddenError(f"approver {approver!r} cannot access {req['repo']!r}")
        if req["action"] == "suite.release" and "*" not in allowed_repos:
            raise ForbiddenError("suite.release requires wildcard ownership")
        if req["action"] == "suite.release" and mode == "delegate_30m":
            raise ForbiddenError("suite.release cannot create delegations")
        if req["status"] != "pending":
            return req

        if mode == "deny":
            c.execute(
                "UPDATE requests SET status='denied', deny_reason=?, decided_by=?, decided_at=? WHERE id=?",
                (deny_reason.strip() or "denied by approver", approver, now, req_id),
            )
        else:
            if req["action"] == "suite.release":
                seq = int(req.get("suite_seq") or 0)
                rel_row = c.execute(
                    "SELECT last_seq FROM suite_releases WHERE upstream_repo=?",
                    (req["repo"],),
                ).fetchone()
                if rel_row is not None and seq <= int(rel_row["last_seq"]):
                    raise SuiteSeqConflictError(
                        f"suite_seq {seq} <= last_released_seq {rel_row['last_seq']}"
                    )
                c.execute(
                    "INSERT OR REPLACE INTO suite_releases(upstream_repo, last_seq, tree_sha256, updated_at) VALUES(?,?,?,?)",
                    (req["repo"], seq, req["target_sha256"], now),
                )
            deleg_id = None
            if mode == "delegate_30m":
                deleg_id = f"del-{uuid.uuid4().hex[:10]}"
                c.execute(
                    "INSERT INTO delegations(id, repo, action, approver, expires_at, created_at) VALUES(?,?,?,?,?,?)",
                    (deleg_id, req["repo"], req["action"], approver, now + 1800, now),
                )
            receipt = self._sign_req_receipt(req, decided_by=approver, delegation_id=deleg_id)
            c.execute(
                "UPDATE requests SET status='approved', decided_by=?, receipt_json=?, decided_at=? WHERE id=?",
                (approver, json.dumps(receipt), now, req_id),
            )
        updated = c.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
        return self._row_to_dict(updated)

    def decide_request(self, req_id: str, mode: str, *, approver: str,
                       allowed_repos: frozenset[str], deny_reason: str = "") -> dict[str, Any] | None:
        if mode not in ("single", "delegate_30m", "deny"):
            raise ValueError(f"invalid decide mode: {mode!r}")
        now = int(time.time())
        with self._tx() as c:
            return self._decide_one_in_tx(
                c, req_id, mode, approver=approver,
                allowed_repos=allowed_repos, deny_reason=deny_reason, now=now,
            )

    def decide_batch(self, decisions: list[dict[str, Any]], *, approver: str,
                     allowed_repos: frozenset[str]) -> list[dict[str, Any]]:
        if not isinstance(decisions, list) or not decisions:
            raise ValueError("decisions must be a non-empty list")
        now = int(time.time())
        with self._tx() as c:
            out: list[dict[str, Any]] = []
            for item in decisions:
                if not isinstance(item, dict) or not str(item.get("req_id") or "").strip():
                    raise ValueError("each decision requires non-empty req_id")
                req_id = str(item["req_id"]).strip()
                raw_mode = item.get("mode")
                mode = "single" if raw_mode is None else str(raw_mode)
                reason = str(item.get("deny_reason") or "")
                res = self._decide_one_in_tx(
                    c, req_id, mode, approver=approver,
                    allowed_repos=allowed_repos, deny_reason=reason, now=now,
                )
                if res is None:
                    raise KeyError(req_id)
                out.append(res)
            return out

    def withdraw_request(self, req_id: str, *, actor: str, allowed_repos: frozenset[str],
                         reason: str = "") -> dict[str, Any] | None:
        now = int(time.time())
        with self._tx() as c:
            row = c.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
            if row is None:
                return None
            req = self._row_to_dict(row)
            if not can_access_repo(allowed_repos, req["repo"]):
                raise ForbiddenError(f"actor {actor!r} cannot withdraw {req['repo']!r}")
            if req["status"] != "pending":
                return req
            c.execute(
                "UPDATE requests SET status='withdrawn', deny_reason=?, decided_by=?, decided_at=? WHERE id=?",
                (reason.strip() or "withdrawn by submitter", actor, now, req_id),
            )
            updated = c.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
            return self._row_to_dict(updated)

    def list_delegations(self, allowed_repos: frozenset[str]) -> tuple[list[dict[str, Any]], list[str]]:
        c = self._conn()
        now = int(time.time())
        rev = self.list_revocations()
        if not allowed_repos:
            return [], rev
        if "*" in allowed_repos:
            rows = c.execute("SELECT * FROM delegations WHERE expires_at > ? ORDER BY created_at DESC", (now,)).fetchall()
        else:
            placeholders = ",".join("?" for _ in allowed_repos)
            rows = c.execute(
                f"SELECT * FROM delegations WHERE repo IN ({placeholders}) AND expires_at > ? ORDER BY created_at DESC",
                [*sorted(allowed_repos), now],
            ).fetchall()
        return [dict(r) for r in rows], rev

    def revoke_id(self, target_id: str, *, allowed_repos: frozenset[str]) -> bool:
        now = int(time.time())
        with self._tx() as c:
            row = c.execute("SELECT repo FROM delegations WHERE id=?", (target_id,)).fetchone()
            if row is not None and not can_access_repo(allowed_repos, str(row["repo"])):
                raise ForbiddenError("cannot revoke delegation for another repo")
            if row is None and "*" not in allowed_repos:
                raise ForbiddenError("only wildcard owner can revoke arbitrary id")
            c.execute("INSERT OR IGNORE INTO revocations(id, revoked_at) VALUES(?,?)", (target_id, now))
        return True

    def list_revocations(self) -> list[str]:
        rows = self._conn().execute("SELECT id FROM revocations ORDER BY id").fetchall()
        return [str(r["id"]) for r in rows]

    @staticmethod
    def _parse_exp_ts(raw_exp: Any) -> float | None:
        if isinstance(raw_exp, (int, float)):
            return float(raw_exp)
        if isinstance(raw_exp, str) and raw_exp.strip():
            txt = raw_exp.strip()
            try:
                return float(txt)
            except ValueError:
                try:
                    norm = txt[:-1] + "+00:00" if txt.endswith("Z") else txt
                    dt = datetime.fromisoformat(norm)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=UTC)
                    return dt.timestamp()
                except ValueError:
                    return None
        return None

    def list_approved_receipts(self, repo: str, *, include_expired: bool = False,
                               limit: int = 200) -> list[dict[str, Any]]:
        """Read-only fetch of active non-revoked receipts for `repo` (newest per transition)."""
        now = int(time.time())
        c = self._conn()
        revoked = {str(r["id"]) for r in c.execute("SELECT id FROM revocations").fetchall()}
        rows = c.execute(
            """SELECT action, target_path, prev_sha256, target_sha256, suite_seq, receipt_json
               FROM requests
               WHERE repo=? AND status IN ('approved', 'approved_delegated') AND receipt_json IS NOT NULL
               ORDER BY COALESCE(decided_at, created_at) DESC, created_at DESC, rowid DESC""",
            (repo,),
        ).fetchall()
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str, Any]] = set()
        for r in rows:
            key = (
                str(r["action"]), str(r["target_path"]),
                str(r["prev_sha256"]), str(r["target_sha256"]), r["suite_seq"],
            )
            if key in seen:
                continue
            try:
                rec = json.loads(str(r["receipt_json"]))
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            body = rec["payload"] if isinstance(rec.get("payload"), dict) else rec
            if str(body.get("id") or "") in revoked or str(body.get("delegation_id") or "") in revoked:
                continue
            if not include_expired:
                exp_ts = self._parse_exp_ts(body.get("expires_at"))
                if exp_ts is None or exp_ts <= now:
                    continue
            seen.add(key)
            out.append(rec)
            if len(out) >= limit:
                break
        return out
