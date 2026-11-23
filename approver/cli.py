"""CLI entrypoint for Einfacht Approver v2 daemon."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import crypto
from .server import create_server
from .store import ApproverStore
from .webhooks import RepoWebhookDispatcher


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Einfacht Approver v2 Control Plane")
    parser.add_argument("--host", default=os.environ.get("APPROVER_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("APPROVER_PORT", "18443")))
    parser.add_argument("--state-dir", default=os.environ.get("APPROVER_STATE_DIR", "/var/lib/einfacht-approver"))
    parser.add_argument("--pass-file", default=os.environ.get("APPROVER_PASS_FILE", "/etc/einfacht-approver/admin.pass"))
    parser.add_argument("--webhook-file", default=os.environ.get("APPROVER_WEBHOOK_FILE", "/etc/einfacht-approver/webhook.url"))
    parser.add_argument("--decision-webhook-file", default=os.environ.get("APPROVER_DECISION_WEBHOOK_FILE", "/etc/einfacht-approver/decision-webhook.url"))
    parser.add_argument("--hash-pass", action="store_true", help="Read passphrase from stdin and print PBKDF2 hash")
    parser.add_argument("--issue-thread-token", nargs=1, metavar="THREAD_ID",
                        help="Issue a bearer token for THREAD_ID (combine with --repos to bind in one step)")
    parser.add_argument("--repos", default="",
                        help="Comma-separated repos to bind when using --issue-thread-token")
    parser.add_argument("--bind-keychain", nargs="+", metavar="ARG",
                        help="Bind repos to THREAD_ID: --bind-keychain <THREAD_ID> <REPO1,REPO2,...>")
    parser.add_argument("--list-keychains", action="store_true", help="List all THREAD_ID -> bound repos")
    args = parser.parse_args(argv)

    if args.hash_pass:
        pw = sys.stdin.read().rstrip("\r\n")
        print(crypto.hash_passphrase(pw))
        return 0

    store = ApproverStore(Path(args.state_dir), Path(args.pass_file))
    if args.list_keychains:
        for tid, repos in store.list_all_keychains().items():
            print(f"{tid}: {', '.join(repos)}")
        store.close()
        return 0
    if args.bind_keychain:
        if len(args.bind_keychain) < 2:
            store.close()
            raise SystemExit("usage: --bind-keychain <THREAD_ID> <REPO1,REPO2,...>")
        ap_name = args.bind_keychain[0]
        raw_repos = [r for arg in args.bind_keychain[1:] for r in arg.split(",")]
        bound = store.bind_keychain_many(ap_name, raw_repos)
        store.close()
        print(f"bound thread={ap_name!r} repos={bound}")
        return 0
    if args.issue_thread_token:
        tid = args.issue_thread_token[0]
        if args.repos:
            store.bind_keychain_many(tid, args.repos.split(","))
        tok = store.issue_thread_token(tid)
        store.close()
        print(tok)
        return 0
    dispatcher = RepoWebhookDispatcher(Path(args.webhook_file), Path(args.decision_webhook_file))
    srv = create_server(args.host, args.port, store, dispatcher)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        dispatcher.flush_all()
        srv.server_close()
    return 0
