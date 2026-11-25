"""Tests for auto-superseding stale pending requests, batch decide, and withdraw."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from approver.crypto import hash_passphrase
from approver.server import create_server
from approver.store import ApproverStore
from approver.webhooks import RepoWebhookDispatcher


def _http(url: str, *, method: str = "GET", body: dict | None = None,
          headers: dict[str, str] | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = dict(headers or {})
    if body is not None:
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class AutoSupersedeAndBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        root = Path(self._td.name)
        pass_file = root / "admin.pass"
        pass_file.write_text(hash_passphrase("pw") + "\n", encoding="utf-8")
        self.store = ApproverStore(root / "state", pass_file)
        self.dispatcher = RepoWebhookDispatcher(root / "wh.url", root / "dwh.url")
        self.srv = create_server("127.0.0.1", 0, self.store, self.dispatcher)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.tok_a = self.store.issue_thread_token("thread-a")
        self.store.bind_keychain_many("thread-a", ["org/repo-a"])
        self.tok_b = self.store.issue_thread_token("thread-b")
        self.store.bind_keychain_many("thread-b", ["org/repo-b"])

    def tearDown(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.dispatcher.flush_all()
        self.store.close()
        self._td.cleanup()

    def test_auto_supersedes_pending_never_touches_denied(self) -> None:
        hdr_a = {"Authorization": f"Bearer {self.tok_a}"}
        # First draft denied -> rejected_duplicate must survive later revisions
        _, r_denied = _http(self.url + "/requests", method="POST", body={
            "repo": "org/repo-a", "action": "question.modify",
            "target_path": "questions/01.md", "prev_sha256": "p0", "target_sha256": "bad1",
        })
        c_den, _ = _http(self.url + "/api/decide", method="POST", headers=hdr_a, body={
            "req_id": r_denied["id"], "mode": "deny", "deny_reason": "weakened",
        })
        self.assertEqual(c_den, 200)

        # Submit v2 then v3 for the same target -> v2 auto-superseded by v3, denied stays denied
        _, r2 = _http(self.url + "/requests", method="POST", body={
            "repo": "org/repo-a", "action": "question.modify",
            "target_path": "questions/01.md", "prev_sha256": "p0", "target_sha256": "sha2",
        })
        _, r3 = _http(self.url + "/requests", method="POST", body={
            "repo": "org/repo-a", "action": "question.modify",
            "target_path": "questions/01.md", "prev_sha256": "p0", "target_sha256": "sha3",
        })
        _, pending = _http(self.url + "/api/pending", headers=hdr_a)
        self.assertEqual([x["id"] for x in pending["requests"]], [r3["id"]])

        _, r2_after = _http(self.url + f"/requests/{r2['id']}")
        self.assertEqual(r2_after["status"], "superseded")
        self.assertIn(r3["display_id"], r2_after["deny_reason"])

        # Resubmitting denied hash still triggers rejected_duplicate
        _, r_dup = _http(self.url + "/requests", method="POST", body={
            "repo": "org/repo-a", "action": "question.modify",
            "target_path": "questions/01.md", "prev_sha256": "p0", "target_sha256": "bad1",
        })
        self.assertEqual(r_dup["status"], "rejected_duplicate")

    def test_batch_decide_atomic_and_withdraw_rbac(self) -> None:
        hdr_a = {"Authorization": f"Bearer {self.tok_a}"}
        hdr_b = {"Authorization": f"Bearer {self.tok_b}"}
        _, a1 = _http(self.url + "/requests", method="POST", body={
            "repo": "org/repo-a", "action": "gate.off",
            "target_path": "knobs.json", "prev_sha256": "k0", "target_sha256": "k1",
        })
        _, a2 = _http(self.url + "/requests", method="POST", body={
            "repo": "org/repo-a", "action": "gate.off",
            "target_path": "check_x.py", "prev_sha256": "on", "target_sha256": "off",
        })
        _, b1 = _http(self.url + "/requests", method="POST", body={
            "repo": "org/repo-b", "action": "seal.core",
            "target_path": "zreflect/SEAL.json", "prev_sha256": "s0", "target_sha256": "s1",
        })

        # Mixed batch touching repo-b via repo-a token must 403 and roll back a1 too
        c_mix, _ = _http(self.url + "/api/decide-batch", method="POST", headers=hdr_a, body={
            "decisions": [{"req_id": a1["id"], "mode": "single"}, {"req_id": b1["id"], "mode": "single"}],
        })
        self.assertEqual(c_mix, 403)
        self.assertEqual(_http(self.url + f"/requests/{a1['id']}")[1]["status"], "pending")

        # Homogeneous batch for repo-a commits atomically
        c_ok, res = _http(self.url + "/api/decide-batch", method="POST", headers=hdr_a, body={
            "decisions": [
                {"req_id": a1["id"], "mode": "single"},
                {"req_id": a2["id"], "mode": "deny", "deny_reason": "keep on"},
            ],
        })
        self.assertEqual(c_ok, 200)
        self.assertEqual([x["status"] for x in res["results"]], ["approved", "denied"])

        # Withdraw b1 requires repo-b scope; denied item a2 cannot be withdrawn
        self.assertEqual(_http(self.url + "/api/withdraw", method="POST", headers=hdr_a, body={"req_id": b1["id"]})[0], 403)
        c_w, w_res = _http(self.url + "/api/withdraw", method="POST", headers=hdr_b, body={
            "req_id": b1["id"], "reason": "reverted locally",
        })
        self.assertEqual(c_w, 200)
        self.assertEqual(w_res["status"], "withdrawn")
        _, a2_stay = _http(self.url + "/api/withdraw", method="POST", headers=hdr_a, body={"req_id": a2["id"]})
        self.assertEqual(a2_stay["status"], "denied")


if __name__ == "__main__":
    unittest.main()
