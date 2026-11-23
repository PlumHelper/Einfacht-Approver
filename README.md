# Einfacht-Approver

Standalone out-of-band Ed25519 approval control plane for multi-repo Einfacht fleets.

## Two-Path Auth Model
1. **Human Owner (`admin.pass`)**: manages all repos, binds/unbinds thread keychains, and issues per-thread bearer tokens (`ef-tok-...`) via the Web UI (`http://127.0.0.1:18443`) or CLI.
2. **Approver Sessions (`T3CODE_THREAD_ID` + Bearer Token)**: each approver thread receives its temporary `ef-tok-...` via `request_secret` and can autonomously view and decide **only** the repos bound to its `THREAD_ID` keychain (`403` on any unbound repo).

All Ed25519 signing keys (`signing_key.pem`) remain strictly on the `root`/admin control plane; every signed receipt binds `"repo"` inside the Ed25519 signature.

## Bind Many Repos to One Thread ID
```bash
# CLI: bind multiple repos and issue a token in one command
python3 -m approver --issue-thread-token <THREAD_ID> --repos ArchivalEra/Einfacht,org/repo-01,org/repo-02

# Or bind/unbind via Web UI at http://127.0.0.1:18443 ("Thread Keychains")
```

## Run Tests
```bash
python3 -m unittest discover -s tests -v
```

## License

Licensed under the [Mozilla Public License Version 2.0](LICENSE) (MPL-2.0).
