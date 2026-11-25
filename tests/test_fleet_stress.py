"""16-repo x 5-approver high-concurrency fleet stress tests for Einfacht Approver v2."""
from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from approver import crypto
from approver.server import create_server
from approver.store import ApproverStore, ForbiddenError


def _find_einfacht_zreflect() -> Path:
    env_p = os.environ.get("EINFACHT_ROOT")
    if env_p:
        return Path(env_p) / "zreflect"
    here = Path(__file__).resolve()
    for base in (here.parents[2], here.parents[3]):
        for cand in (base / "Einfacht", base / "zcode-projects" / "Einfacht"):
            if (cand / "zreflect" / "trust_core.py").is_file():
                return cand / "zreflect"
    return here.parents[2] / "Einfacht" / "zreflect"


EINFACHT_ZREFLECT = _find_einfacht_zreflect()


def _http(url: str, *, method: str = "GET", body: dict | None = None,
          headers: dict[str, str] | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = dict(headers or {})
    if data is not None:
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


class FleetStressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.pass_file = root / "admin.pass"

        repos = [f"org/repo-{i:02d}" for i in range(1, 17)]
        self.repos = repos
        self.passes = {
            "owner": ("pass-owner", "*"),
            "shard_a": ("pass-a", "org/empty"),
            "shard_b": ("pass-b", "org/empty"),
            "shard_c": ("pass-c", "org/empty"),
            "nobody": ("pass-nobody", "org/empty"),
        }
        lines = [
            f"{name}:{scope}:{crypto.hash_passphrase(pw)}"
            for name, (pw, scope) in self.passes.items()
        ]
        self.pass_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        self.store = ApproverStore(root / "state", self.pass_file)
        # Bind slices into each approver's keychain in one batch per approver
        self.store.bind_keychain_many("shard_a", repos[0:5])
        self.store.bind_keychain_many("shard_b", repos[5:10])
        self.store.bind_keychain_many("shard_c", repos[10:15])
        self.srv = create_server("127.0.0.1", 0, self.store)
        self.base_url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.srv_thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.srv_thread.start()

    def tearDown(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.store.close()
        self.tmp.cleanup()

    def test_01_login_page_renders_200(self) -> None:
        with urllib.request.urlopen(self.base_url + "/", timeout=5) as r:
            self.assertEqual(r.status, 200)
            html_body = r.read().decode("utf-8")
            self.assertIn("Einfacht Isolated Approver v2", html_body)

    def test_02_16_repo_concurrent_requests_zero_crosstalk(self) -> None:
        def submit_one(idx: int) -> tuple[int, dict]:
            repo = self.repos[idx % 16]
            return _http(self.base_url + "/requests", method="POST", body={
                "repo": repo,
                "agent_id": f"agent-{idx}",
                "action": "gate.off",
                "target_path": f"knobs-{idx}.json",
                "prev_sha256": "NONE",
                "target_sha256": f"{idx:064x}",
            })

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(submit_one, range(80)))

        self.assertTrue(all(code in (200, 201) for code, _ in results))
        req_ids = [(r["repo"], r["id"]) for _, r in results]

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            dec_results = list(pool.map(
                lambda item: _http(
                    self.base_url + "/api/decide", method="POST",
                    headers={"X-Approver-Pass": self.passes["owner"][0]},
                    body={"req_id": item[1], "mode": "single"},
                ),
                req_ids,
            ))
        self.assertTrue(all(code == 200 and body["status"] == "approved" for code, body in dec_results))

        for repo in self.repos:
            code, rec_resp = _http(self.base_url + f"/receipts?repo={repo}")
            self.assertEqual(code, 200)
            self.assertEqual(len(rec_resp["receipts"]), 5)
            self.assertTrue(all(rec["repo"] == repo for rec in rec_resp["receipts"]))

    def test_03_rbac_cross_repo_and_suite_release_forbidden(self) -> None:
        _, r1 = _http(self.base_url + "/requests", method="POST", body={
            "repo": "org/repo-06", "action": "gate.off", "target_path": "knobs.json",
            "prev_sha256": "NONE", "target_sha256": "a" * 64,
        })
        # shard_a (repos 01..05) cannot see or decide org/repo-06
        code_list, body_list = _http(
            self.base_url + "/api/requests",
            headers={"X-Approver-Pass": self.passes["shard_a"][0]},
        )
        self.assertEqual(code_list, 200)
        self.assertFalse(any(x["id"] == r1["id"] for x in body_list["requests"]))

        code_dec, _ = _http(
            self.base_url + "/api/decide", method="POST",
            headers={"X-Approver-Pass": self.passes["shard_a"][0]},
            body={"req_id": r1["id"], "mode": "single"},
        )
        self.assertEqual(code_dec, 403)

        # nobody cannot approve anything; shard_b cannot approve suite.release for ArchivalEra/Einfacht
        _, sr = _http(self.base_url + "/requests", method="POST", body={
            "repo": "ArchivalEra/Einfacht", "action": "suite.release",
            "target_path": "zreflect/SEAL.json", "prev_sha256": "0" * 64,
            "target_sha256": "b" * 64, "suite_seq": 1,
        })
        code_sr, _ = _http(
            self.base_url + "/api/decide", method="POST",
            headers={"X-Approver-Pass": self.passes["shard_b"][0]},
            body={"req_id": sr["id"], "mode": "single"},
        )
        self.assertEqual(code_sr, 403)

        # Even owner cannot delegate_30m a suite.release
        code_del, _ = _http(
            self.base_url + "/api/decide", method="POST",
            headers={"X-Approver-Pass": self.passes["owner"][0]},
            body={"req_id": sr["id"], "mode": "delegate_30m"},
        )
        self.assertEqual(code_del, 403)

    def test_04_cross_repo_receipt_replay_rejected(self) -> None:
        same_prev, same_target = "1" * 64, "2" * 64
        _, req_a = _http(self.base_url + "/requests", method="POST", body={
            "repo": "org/repo-01", "action": "seal.core",
            "target_path": "reflect-local/measure_app.py",
            "prev_sha256": same_prev, "target_sha256": same_target,
        })
        _, dec_a = _http(
            self.base_url + "/api/decide", method="POST",
            headers={"X-Approver-Pass": self.passes["shard_a"][0]},
            body={"req_id": req_a["id"], "mode": "single"},
        )
        rec_a = dec_a["receipt"]
        self.assertEqual(rec_a["repo"], "org/repo-01")
        self.assertNotEqual(rec_a["repo"], "org/repo-02")
        if not (EINFACHT_ZREFLECT / "trust_core.py").is_file():
            return
        if str(EINFACHT_ZREFLECT) not in sys.path:
            sys.path.insert(0, str(EINFACHT_ZREFLECT))
        import trust  # type: ignore[import-not-found]
        import trust_core  # type: ignore[import-not-found]

        _, pub_resp = _http(self.base_url + "/pubkey")
        pub_pem = pub_resp["public_key_pem"]

        self.assertEqual(
            trust_core.verify_receipt(
                rec_a, repo_name="org/repo-01", action="seal.core",
                target="reflect-local/measure_app.py",
                prev_sha256=same_prev, target_sha256=same_target,
                pub_b64=pub_pem, verify_sig_fn=trust.ed25519_verify,
            ),
            [],
        )
        replay_probs = trust_core.verify_receipt(
            rec_a, repo_name="org/repo-02", action="seal.core",
            target="reflect-local/measure_app.py",
            prev_sha256=same_prev, target_sha256=same_target,
            pub_b64=pub_pem, verify_sig_fn=trust.ed25519_verify,
        )
        self.assertEqual([p.code for p in replay_probs], ["approval.scope_mismatch"])

    def test_05_suite_seq_concurrent_race_and_downgrade(self) -> None:
        req_ids = []
        for i in range(8):
            code, r = _http(self.base_url + "/requests", method="POST", body={
                "repo": "ArchivalEra/Einfacht", "action": "suite.release",
                "target_path": "zreflect/SEAL.json", "prev_sha256": "0" * 64,
                "target_sha256": f"{i + 10:064x}", "suite_seq": 2,
            })
            self.assertIn(code, (200, 201))
            req_ids.append(r["id"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            decs = list(pool.map(
                lambda rid: _http(
                    self.base_url + "/api/decide", method="POST",
                    headers={"X-Approver-Pass": self.passes["owner"][0]},
                    body={"req_id": rid, "mode": "single"},
                ),
                req_ids,
            ))
        ok_count = sum(1 for code, _ in decs if code == 200)
        conflict_count = sum(1 for code, _ in decs if code == 409)
        self.assertEqual(ok_count, 1)
        self.assertEqual(conflict_count, 7)

        # Old seq=1 must be rejected with 409
        code_old, _ = _http(self.base_url + "/requests", method="POST", body={
            "repo": "ArchivalEra/Einfacht", "action": "suite.release",
            "target_path": "zreflect/SEAL.json", "prev_sha256": "0" * 64,
            "target_sha256": "f" * 64, "suite_seq": 1,
        })
        self.assertEqual(code_old, 409)

    def test_06_1200_history_p99_and_denied_dedup(self) -> None:
        for i in range(1200):
            self.store.submit_request({
                "repo": self.repos[i % 16], "action": "gate.off",
                "target_path": f"file-{i}.json", "prev_sha256": "NONE",
                "target_sha256": f"{i:064x}",
            })
        # Create one denied request and verify same-SHA resubmission returns rejected_duplicate
        _, denied_req = _http(self.base_url + "/requests", method="POST", body={
            "repo": "org/repo-01", "action": "gate.off", "target_path": "knobs.json",
            "prev_sha256": "NONE", "target_sha256": "d" * 64,
        })
        _http(
            self.base_url + "/api/decide", method="POST",
            headers={"X-Approver-Pass": self.passes["owner"][0]},
            body={"req_id": denied_req["id"], "mode": "deny", "deny_reason": "too permissive"},
        )

        latencies_ms = []
        for _ in range(50):
            t0 = time.perf_counter()
            code, resp = _http(self.base_url + "/requests", method="POST", body={
                "repo": "org/repo-01", "action": "gate.off", "target_path": "knobs.json",
                "prev_sha256": "NONE", "target_sha256": "d" * 64,
            })
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            self.assertEqual(code, 200)
            self.assertEqual(resp["status"], "rejected_duplicate")
            self.assertEqual(resp["deny_reason"], "too permissive")
        p99 = sorted(latencies_ms)[int(len(latencies_ms) * 0.99)]
        self.assertLess(p99, 100.0)

    def test_07_thread_token_keychain_isolation(self) -> None:
        # Bind multiple repos AND issue a thread token in one HTTP call
        code, bind_resp = _http(
            self.base_url + "/api/keychain/bind", method="POST",
            headers={"X-Approver-Pass": self.passes["owner"][0]},
            body={
                "approver": "tid-bot-reviewer",
                "repos": ["org/repo-01", "org/repo-02", "org/repo-03"],
                "issue_token": True,
            },
        )
        self.assertEqual(code, 200)
        self.assertEqual(bind_resp["repos"], ["org/repo-01", "org/repo-02", "org/repo-03"])
        tok = bind_resp["token"]

        # Unbind org/repo-03 and confirm 403 on org/repo-03 while org/repo-01 succeeds
        c_un, _ = _http(
            self.base_url + "/api/keychain/unbind", method="POST",
            headers={"X-Approver-Pass": self.passes["owner"][0]},
            body={"approver": "tid-bot-reviewer", "repo": "org/repo-03"},
        )
        self.assertEqual(c_un, 200)

        bearer = {"Authorization": f"Bearer {tok}"}
        _, req1 = _http(self.base_url + "/requests", method="POST", body={
            "repo": "org/repo-01", "action": "gate.off", "target_path": "knobs.json",
            "prev_sha256": "NONE", "target_sha256": "e" * 64,
        })
        _, req3 = _http(self.base_url + "/requests", method="POST", body={
            "repo": "org/repo-03", "action": "gate.off", "target_path": "knobs.json",
            "prev_sha256": "NONE", "target_sha256": "f" * 64,
        })
        c_d1, dec1 = _http(self.base_url + "/api/decide", method="POST", headers=bearer,
                           body={"req_id": req1["id"], "mode": "single"})
        self.assertEqual(c_d1, 200)
        self.assertIn("receipt", dec1)
        c_d3, _ = _http(self.base_url + "/api/decide", method="POST", headers=bearer,
                        body={"req_id": req3["id"], "mode": "single"})
        self.assertEqual(c_d3, 403)

        # Also verify the same ef-tok-... works via X-Approver-Pass and Web UI /login
        c_xp, xp_list = _http(self.base_url + "/api/requests", headers={"X-Approver-Pass": tok})
        self.assertEqual(c_xp, 200)
        self.assertEqual(xp_list["approver"], "tid-bot-reviewer")
        login_req = urllib.request.Request(
            self.base_url + "/login",
            data=urllib.parse.urlencode({"passphrase": tok}).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        with opener.open(login_req, timeout=5) as r_login:
            self.assertEqual(r_login.status, 200)
            bot_html = r_login.read().decode("utf-8")
            self.assertIn("tid-bot-reviewer", bot_html)
            # Non-admin MUST NOT see Thread Keychains or any raw ef-tok-... token in the HTML
            self.assertNotIn("Thread Keychains", bot_html)
            self.assertNotIn(tok, bot_html)

        # Store-level RBAC: non-admin cannot call list_thread_tokens
        with self.assertRaises(ForbiddenError):
            self.store.list_thread_tokens(frozenset({"org/repo-01"}))

        # Admin logging into Web UI CAN always view and copy the persisted token + no-scroll-jump JS
        admin_login = urllib.request.Request(
            self.base_url + "/login",
            data=urllib.parse.urlencode({"passphrase": self.passes["owner"][0]}).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        admin_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        with admin_opener.open(admin_login, timeout=5) as r_admin:
            self.assertEqual(r_admin.status, 200)
            admin_html = r_admin.read().decode("utf-8")
            self.assertIn("Thread Keychains", admin_html)
            self.assertIn(tok, admin_html)
            self.assertIn("Copy Token", admin_html)
            self.assertIn("window.scrollTo(x,y)", admin_html)

    def test_08_5_approvers_16_repos_concurrent_keychain_stress(self) -> None:
        bots: dict[str, tuple[str, list[str]]] = {}
        for b in range(5):
            tid = f"tid-bot-{b + 1}"
            tok = self.store.issue_thread_token(tid)
            assigned = [self.repos[i] for i in range(b * 3, min(16, (b + 1) * 3 + (1 if b == 4 else 0)))]
            self.store.bind_keychain_many(tid, assigned)
            bots[tid] = (tok, assigned)

        req_by_repo: dict[str, list[str]] = {}
        for i in range(32):
            repo = self.repos[i % 16]
            _, req_d = _http(self.base_url + "/requests", method="POST", body={
                "repo": repo, "action": "gate.off", "target_path": f"k-{i}.json",
                "prev_sha256": "NONE", "target_sha256": f"{i + 100:064x}",
            })
            req_by_repo.setdefault(repo, []).append(req_d["id"])

        def run_bot(tid: str) -> tuple[int, int]:
            tok, assigned = bots[tid]
            hdr = {"Authorization": f"Bearer {tok}"}
            ok_cnt = 0
            for repo in assigned:
                for rid in req_by_repo.get(repo, []):
                    code, dec = _http(self.base_url + "/api/decide", method="POST", headers=hdr,
                                      body={"req_id": rid, "mode": "single"})
                    self.assertEqual(code, 200)
                    self.assertIn("receipt", dec)
                    ok_cnt += 1
            other_repo = next(r for r in self.repos if r not in assigned)
            c_403, _ = _http(self.base_url + "/api/decide", method="POST", headers=hdr,
                             body={"req_id": req_by_repo[other_repo][0], "mode": "single"})
            return ok_cnt, c_403

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            res = list(pool.map(run_bot, sorted(bots)))
        self.assertEqual(sum(ok for ok, _ in res), 32)
        self.assertTrue(all(c == 403 for _, c in res))

    def test_09_security_input_validation(self) -> None:
        # 1. Invalid decide mode must return 400 (never silently approve)
        _, req = _http(self.base_url + "/requests", method="POST", body={
            "repo": "org/repo-01", "action": "gate.off", "target_path": "knobs.json",
            "prev_sha256": "NONE", "target_sha256": "9" * 64,
        })
        c_bad_mode, _ = _http(
            self.base_url + "/api/decide", method="POST",
            headers={"X-Approver-Pass": self.passes["owner"][0]},
            body={"req_id": req["id"], "mode": "bogus_mode"},
        )
        self.assertEqual(c_bad_mode, 400)
        _, polled = _http(self.base_url + f"/requests/{req['id']}")
        self.assertEqual(polled["status"], "pending")

        # 2. Non-integer suite_seq must return 400
        c_bad_seq, _ = _http(self.base_url + "/requests", method="POST", body={
            "repo": "ArchivalEra/Einfacht", "action": "suite.release",
            "target_path": "zreflect/SEAL.json", "prev_sha256": "0" * 64,
            "target_sha256": "8" * 64, "suite_seq": "not-an-int",
        })
        self.assertEqual(c_bad_seq, 400)

        # Verify plaintext single-line admin.pass also works alongside hashed entries
        self.assertEqual(crypto.verify_passphrase("my-plain-pw\n", "my-plain-pw"), ("admin", frozenset({"*"})))
        self.assertIsNone(crypto.verify_passphrase("my-plain-pw\n", "wrong"))

        # 3. Oversized payload (> 1 MiB) must return 413
        import http.client
        import urllib.parse

        parsed = urllib.parse.urlparse(self.base_url)
        conn = http.client.HTTPConnection(parsed.hostname or "127.0.0.1", parsed.port, timeout=5)
        conn.putrequest("POST", "/requests")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "1048577")
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        conn.close()

        # 4. Expired receipt must NOT deduplicate as active — creates fresh pending request
        exp_rec = json.dumps({"expires_at": int(time.time()) - 10, "sig": "old"})
        req_exp, _ = self.store.submit_request({
            "repo": "org/repo-02", "action": "gate.off", "target_path": "exp.json",
            "prev_sha256": "NONE", "target_sha256": "e" * 64,
        })
        self.store._conn().execute(
            "UPDATE requests SET status='approved', receipt_json=? WHERE id=?",
            (exp_rec, req_exp["id"]),
        )
        fresh_req, is_new = self.store.submit_request({
            "repo": "org/repo-02", "action": "gate.off", "target_path": "exp.json",
            "prev_sha256": "NONE", "target_sha256": "e" * 64,
        })
        self.assertTrue(is_new)
        self.assertEqual(fresh_req["status"], "pending")
        self.assertNotEqual(fresh_req["id"], req_exp["id"])


if __name__ == "__main__":
    unittest.main()
