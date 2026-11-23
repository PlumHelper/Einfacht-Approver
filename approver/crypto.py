"""Ed25519 signing, verification, and PBKDF2 passphrase hashing for Approver v2."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON bytes for Ed25519 signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_or_create_keypair(state_dir: Path) -> tuple[Ed25519PrivateKey, str, str]:
    """Load or generate Ed25519 private key in `state_dir`; return `(priv, pub_pem, key_id)`."""
    state_dir.mkdir(parents=True, exist_ok=True)
    key_path = state_dir / "signing_key.pem"
    pub_path = state_dir / "signing_pub.pem"
    if key_path.is_file():
        loaded = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("signing_key.pem is not Ed25519")
        priv = loaded
    else:
        priv = Ed25519PrivateKey.generate()
        key_path.write_bytes(
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
    pub_pem_bytes = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_pem = pub_pem_bytes.decode("ascii")
    if not pub_path.is_file() or pub_path.read_text("ascii") != pub_pem:
        pub_path.write_text(pub_pem, encoding="ascii")
    key_id = hashlib.sha256(pub_pem_bytes).hexdigest()[:16]
    return priv, pub_pem, key_id


def sign_receipt(priv: Ed25519PrivateKey, payload: dict[str, Any]) -> dict[str, Any]:
    """Sign `payload` with Ed25519 and return `{**payload, 'sig': b64}`."""
    sig_b64 = base64.b64encode(priv.sign(canonical_bytes(payload))).decode("ascii")
    return {**payload, "sig": sig_b64}


def hash_passphrase(passphrase: str, salt: bytes | None = None) -> str:
    """Return `salt_hex:dk_hex` PBKDF2-HMAC-SHA256 digest."""
    s = salt if salt is not None else hashlib.sha256(passphrase.encode("utf-8")).digest()[:16]
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), s, 200_000)
    return f"{s.hex()}:{dk.hex()}"


def parse_pass_entries(raw: str) -> dict[str, tuple[frozenset[str], str, str, bool]]:
    """Parse `admin.pass` lines (`plaintext`, `approver:repos:plaintext`, or PBKDF2 `salt:hash`)."""
    out: dict[str, tuple[frozenset[str], str, str, bool]] = {}
    for ln in raw.splitlines():
        line = ln.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) == 1:
            out["admin"] = (frozenset({"*"}), "", line, True)
        elif len(parts) == 2:
            out["admin"] = (frozenset({"*"}), parts[0], parts[1], False)
        elif len(parts) == 3:
            repos = frozenset(r.strip() for r in parts[1].split(",") if r.strip()) or frozenset({"*"})
            out[parts[0].strip()] = (repos, "", parts[2], True)
        elif len(parts) == 4:
            repos = frozenset(r.strip() for r in parts[1].split(",") if r.strip()) or frozenset({"*"})
            out[parts[0].strip()] = (repos, parts[2], parts[3], False)
    return out


def verify_passphrase(raw_entries: str, passphrase: str) -> tuple[str, frozenset[str]] | None:
    """Verify `passphrase` against `admin.pass` contents; return `(approver, allowed_repos)`."""
    if not passphrase:
        return None
    entries = parse_pass_entries(raw_entries)
    for approver, (repos, salt_hex, secret_or_dk, is_plain) in entries.items():
        if is_plain:
            if hmac.compare_digest(passphrase, secret_or_dk):
                return approver, repos
            continue
        try:
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(secret_or_dk)
        except ValueError:
            continue
        for iters in (200_000, 100_000):
            got = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iters)
            if hmac.compare_digest(got, expected):
                return approver, repos
    return None
