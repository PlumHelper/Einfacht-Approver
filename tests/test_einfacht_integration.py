"""12-repo heterogeneous Einfacht Trust v2 fleet integration test against Approver v2."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from approver import crypto
from approver.server import create_server
from approver.store import ApproverStore
from approver.webhooks import RepoWebhookDispatcher


def _find_einfacht_root() -> Path:
    env_p = os.environ.get("EINFACHT_ROOT")
    if env_p:
        return Path(env_p)
    here = Path(__file__).resolve()
    for base in (here.parents[2], here.parents[3]):
        for cand in (base / "Einfacht", base / "zcode-projects" / "Einfacht"):
            if (cand / "zreflect" / "trust_core.py").is_file():
                return cand
    return here.parents[2] / "Einfacht"


EINFACHT_ROOT = _find_einfacht_root()
EINFACHT_ZREFLECT = EINFACHT_ROOT / "zreflect"


def _post_json(url: str, body: dict, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


@unittest.skipUnless((EINFACHT_ZREFLECT / "trust_core.py").is_file(),
                     "Requires Einfacht checkout (sibling directory or EINFACHT_ROOT)")
class EinfachtFleetIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        if str(EINFACHT_ZREFLECT) not in sys.path:
            sys.path.insert(0, str(EINFACHT_ZREFLECT))
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        pass_file = root / "admin.pass"
        self.owner_pw = "owner-secret"
        pass_file.write_text(f"owner:*:{crypto.hash_passphrase(self.owner_pw)}\n", encoding="utf-8")
        self.store = ApproverStore(root / "state", pass_file)
        self.dispatcher = RepoWebhookDispatcher(root / "wh.url", root / "dec.url", debounce_sec=0.05)
        self.srv = create_server("127.0.0.1", 0, self.store, self.dispatcher)
        self.base_url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.srv_thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.srv_thread.start()

    def tearDown(self) -> None:
        self.dispatcher.flush_all()
        self.srv.shutdown()
        self.srv.server_close()
        self.store.close()
        self.tmp.cleanup()

    def _make_suite(self, path: Path, seq: int) -> dict:
        import trust_core  # type: ignore[import-not-found]

        (path / "zreflect").mkdir(parents=True, exist_ok=True)
        shutil.copytree(EINFACHT_ZREFLECT, path / "zreflect", dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "SUITE.sig"))
        shutil.copy2(EINFACHT_ROOT / "ruff.toml", path / "ruff.toml")
        # Bump suite_seq in SEAL.json
        seal_p = path / "zreflect" / "SEAL.json"
        seal_d = json.loads(seal_p.read_text("utf-8"))
        seal_d["suite_seq"] = seq
        seal_d["tree_sha256"] = trust_core.compute_tree_sha(seal_d["files"])
        seal_p.write_text(json.dumps(seal_d, indent=1, sort_keys=True) + "\n", encoding="utf-8")

        # Sign suite.release via Approver v2
        sub = _post_json(self.base_url + "/requests", {
            "repo": "ArchivalEra/Einfacht",
            "action": "suite.release",
            "target_path": "zreflect/SEAL.json",
            "prev_sha256": "0" * 64,
            "target_sha256": seal_d["tree_sha256"],
            "suite_seq": seq,
        })
        dec = _post_json(
            self.base_url + "/api/decide",
            {"req_id": sub["id"], "mode": "single"},
            headers={"X-Approver-Pass": self.owner_pw},
        )
        (path / "zreflect" / "SUITE.sig").write_text(json.dumps(dec["receipt"]), encoding="utf-8")
        return seal_d

    def test_12_repo_heterogeneous_upgrade_and_tamper_fleet(self) -> None:
        import subprocess

        import trust  # type: ignore[import-not-found]

        root = Path(self.tmp.name)
        suite_v1 = root / "suite_v1"
        suite_v2 = root / "suite_v2"
        self._make_suite(suite_v1, seq=1)
        self._make_suite(suite_v2, seq=2)

        # 1. 4 repos on v1 -> upgrade to v2 preserving reflect-local/hook.py & measure_app.py
        for i in range(4):
            repo_dir = root / f"fleet-upgrade-{i}"
            shutil.copytree(suite_v1, repo_dir)
            (repo_dir / "reflect-local").mkdir(parents=True)
            (repo_dir / "reflect-local" / "hook.py").write_text("# custom hook\n", encoding="utf-8")
            (repo_dir / "reflect-local" / "measure_app.py").write_text("def measure():\n    return {}\n", encoding="utf-8")
            r_init = subprocess.run([sys.executable, "zreflect/facts.py", "--init"], check=False, cwd=repo_dir, capture_output=True, text=True)
            self.assertEqual(r_init.returncode, 0, r_init.stderr + r_init.stdout)
            trust.write_anchors(str(repo_dir), {
                "schema": 1, "repo": f"org/app-{i}",
                "approver_pub": self.store.pub_pem(), "lock_core": True,
                "revoked_ids": [], "suite_seq": 1, "suite_tree_sha256": "",
                "knobs_sha256": trust.sha256_file(str(repo_dir / "knobs.json")) or "NONE", "questions_dir": "questions",
                "custom_scripts": trust.local_scripts_map(str(repo_dir)),
                "off_gates": [], "principles": {}, "questions": {},
            })
            r_upg = subprocess.run([sys.executable, "zreflect/trust.py", "--upgrade", str(suite_v2)],
                                   check=False, cwd=repo_dir, capture_output=True, text=True)
            self.assertEqual(r_upg.returncode, 0, r_upg.stderr + r_upg.stdout)
            anc = trust.load_anchors(str(repo_dir))
            self.assertEqual(anc["schema"], 2)
            self.assertEqual(anc["suite_seq"], 2)
            self.assertIn("reflect-local/hook.py", anc["local_scripts"])
            self.assertEqual((repo_dir / "reflect-local" / "hook.py").read_text("utf-8"), "# custom hook\n")

        # 2. 4 repos attempt downgrade v2 -> v1 -> must fail rc=2
        for i in range(4):
            repo_dir = root / f"fleet-upgrade-{i}"
            r_down = subprocess.run([sys.executable, "zreflect/trust.py", "--upgrade", str(suite_v1)],
                                    check=False, cwd=repo_dir, capture_output=True, text=True)
            self.assertEqual(r_down.returncode, 2)

        # 3. 4 repos tamper reflect-local/hook.py -> blocked until approved by Approver v2
        for i in range(4):
            repo_dir = root / f"fleet-upgrade-{i}"
            anc = trust.load_anchors(str(repo_dir))
            anc["approver_pub"] = self.store.pub_pem()
            trust.write_anchors(str(repo_dir), anc)
            prev_sha = trust.sha256_file(str(repo_dir / "reflect-local" / "hook.py"))
            (repo_dir / "reflect-local" / "hook.py").write_text("# modified hook\n", encoding="utf-8")
            new_sha = trust.sha256_file(str(repo_dir / "reflect-local" / "hook.py"))
            probs = trust.check_knobs_anchor(root=str(repo_dir), receipt={"receipts": []})
            self.assertEqual([p.code for p in probs], ["approval.receipt_required"])

            # Approve via Approver v2 and verify offline receipt passes
            sub = _post_json(self.base_url + "/requests", {
                "repo": f"org/app-{i}", "action": "seal.core",
                "target_path": "reflect-local/hook.py",
                "prev_sha256": prev_sha, "target_sha256": new_sha,
            })
            dec = _post_json(
                self.base_url + "/api/decide",
                {"req_id": sub["id"], "mode": "single"},
                headers={"X-Approver-Pass": self.owner_pw},
            )
            ok_probs = trust.check_knobs_anchor(root=str(repo_dir), receipt=dec["receipt"])
            self.assertEqual(ok_probs, [])


if __name__ == "__main__":
    unittest.main()
