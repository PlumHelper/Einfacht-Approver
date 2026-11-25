"""Tests for dual HTTP + HTTPS listener and TLS session cookie behavior."""
from __future__ import annotations

import ipaddress
import socket
import ssl
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from approver.crypto import hash_passphrase
from approver.server import create_server
from approver.store import ApproverStore


def _write_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class TLSListenerTests(unittest.TestCase):
    def test_dual_http_and_https_with_bad_client_resilience(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pass_file = root / "admin.pass"
            pass_file.write_text(hash_passphrase("owner-secret") + "\n", encoding="utf-8")
            cert_p, key_p = root / "tls.crt", root / "tls.key"
            _write_self_signed_cert(cert_p, key_p)

            store = ApproverStore(root / "state", pass_file)

            http_srv = create_server("127.0.0.1", 0, store)
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
            https_srv = create_server("127.0.0.1", 0, store, ssl_context=ssl_ctx)

            t_http = threading.Thread(target=http_srv.serve_forever, daemon=True)
            t_https = threading.Thread(target=https_srv.serve_forever, daemon=True)
            t_http.start()
            t_https.start()
            try:
                http_port = http_srv.server_address[1]
                https_port = https_srv.server_address[1]

                # Plain TCP garbage hitting the TLS port must not stall/break HTTPS
                with socket.create_connection(("127.0.0.1", https_port), timeout=2) as s:
                    s.sendall(b"NOT_TLS_HELLO\r\n")

                client_ctx = ssl.create_default_context(cafile=str(cert_p))
                with urllib.request.urlopen(
                    f"https://127.0.0.1:{https_port}/pubkey", context=client_ctx, timeout=3
                ) as resp:
                    self.assertEqual(resp.status, 200)
                    self.assertIn("BEGIN PUBLIC KEY", resp.read().decode("utf-8"))

                # Login over HTTPS sets `; Secure` cookie; loopback HTTP omits `; Secure`
                opener_tls = urllib.request.build_opener(
                    _NoRedirect(), urllib.request.HTTPSHandler(context=client_ctx)
                )
                body = urllib.parse.urlencode({"passphrase": "owner-secret"}).encode("utf-8")
                with self.assertRaises(urllib.error.HTTPError) as exc_tls:
                    opener_tls.open(urllib.request.Request(
                        f"https://127.0.0.1:{https_port}/login", data=body, method="POST"
                    ))
                self.assertEqual(exc_tls.exception.code, 303)
                self.assertIn("; Secure", exc_tls.exception.headers.get("Set-Cookie", ""))

                opener_http = urllib.request.build_opener(_NoRedirect())
                with self.assertRaises(urllib.error.HTTPError) as exc_http:
                    opener_http.open(urllib.request.Request(
                        f"http://127.0.0.1:{http_port}/login", data=body, method="POST"
                    ))
                self.assertEqual(exc_http.exception.code, 303)
                self.assertNotIn("; Secure", exc_http.exception.headers.get("Set-Cookie", ""))
            finally:
                https_srv.shutdown()
                https_srv.server_close()
                http_srv.shutdown()
                http_srv.server_close()
                store.close()


if __name__ == "__main__":
    unittest.main()
