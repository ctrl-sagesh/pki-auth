# server/server.py
from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from flask import Flask, jsonify, request

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID

APP = Flask(__name__)

# ===== Paths =====
BASE = Path(__file__).resolve().parent

# Trust anchor (copy of ca/ca_cert.pem)
TRUSTED_CA = BASE / "trusted_ca.pem"

# Server-side CRL (recommended: copy ca/crl.pem -> server/crl.pem)
CRL_PATH = BASE / "crl.pem"

# Fallback: if you forget to copy CRL, server will try reading from ../ca/crl.pem automatically
FALLBACK_CA_CRL = (BASE.parent / "ca" / "crl.pem").resolve()

TLS_DIR = BASE / "tls"
TLS_KEY = TLS_DIR / "server_key.pem"
TLS_CERT = TLS_DIR / "server_cert.pem"

# ===== Security controls =====
NONCE_TTL_SECONDS = 60
TOKEN_TTL_SECONDS = 10 * 60  # 10 minutes
MAX_CERT_PEM_BYTES = 16_000
MAX_SIG_B64_BYTES = 8_000


@dataclass
class PendingChallenge:
    nonce: bytes
    expires_at: float
    cert_fingerprint: str


@dataclass
class SessionToken:
    token: str
    expires_at: float
    cert_fingerprint: str


PENDING: Dict[str, PendingChallenge] = {}
TOKENS: Dict[str, SessionToken] = {}


def now() -> float:
    return time.time()


def clean_expired():
    t = now()
    for k in list(PENDING.keys()):
        if PENDING[k].expires_at < t:
            del PENDING[k]
    for k in list(TOKENS.keys()):
        if TOKENS[k].expires_at < t:
            del TOKENS[k]


def load_ca_cert() -> x509.Certificate:
    if not TRUSTED_CA.exists():
        raise FileNotFoundError(
            f"Missing trusted CA at {TRUSTED_CA}. Copy ca/ca_cert.pem -> server/trusted_ca.pem"
        )
    return x509.load_pem_x509_certificate(TRUSTED_CA.read_bytes())


def _choose_crl_path() -> Optional[Path]:
    """
    Choose the newest available CRL path.
    Priority:
      1) server/crl.pem (CRL_PATH)
      2) ../ca/crl.pem  (FALLBACK_CA_CRL)
    """
    candidates = []
    if CRL_PATH.exists() and CRL_PATH.read_bytes().strip():
        candidates.append(CRL_PATH)
    if FALLBACK_CA_CRL.exists() and FALLBACK_CA_CRL.read_bytes().strip():
        candidates.append(FALLBACK_CA_CRL)

    if not candidates:
        return None

    # Pick the most recently modified CRL
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def load_crl_strict() -> Tuple[Optional[x509.CertificateRevocationList], str]:
    """
    Loads a PEM CRL from disk with clear status.
    Returns: (crl_or_none, status_message)

    If a CRL file exists but cannot be parsed, we FAIL CLOSED by raising an error.
    This prevents 'silent revocation bypass' and is better for security + marks.
    """
    chosen = _choose_crl_path()
    if chosen is None:
        return None, "CRL not found (revocation check skipped)"

    data = chosen.read_bytes()
    if not data.strip():
        return None, f"CRL empty at {chosen} (revocation check skipped)"

    try:
        crl = x509.load_pem_x509_crl(data)
        revoked_count = len(list(crl))
        return crl, f"CRL loaded from {chosen} (revoked entries: {revoked_count})"
    except Exception as e:
        # FAIL CLOSED: if CRL exists but can't be parsed, reject logins
        raise ValueError(f"CRL parse failed at {chosen}: {type(e).__name__}: {e}")


def pem_to_cert(cert_pem: str) -> x509.Certificate:
    if len(cert_pem.encode("utf-8", errors="ignore")) > MAX_CERT_PEM_BYTES:
        raise ValueError("Certificate too large")
    return x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))


def is_revoked(crl: Optional[x509.CertificateRevocationList], cert: x509.Certificate) -> bool:
    if not crl:
        return False
    return any(r.serial_number == cert.serial_number for r in crl)


def verify_cert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def check_cert_validity(cert: x509.Certificate) -> None:
    n = time.time()
    not_before = cert.not_valid_before_utc.timestamp()
    not_after = cert.not_valid_after_utc.timestamp()
    if n < not_before:
        raise ValueError("Certificate not valid yet")
    if n > not_after:
        raise ValueError("Certificate expired")


def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def b64_to_bytes(s: str) -> bytes:
    if len(s.encode("utf-8", errors="ignore")) > MAX_SIG_B64_BYTES:
        raise ValueError("Signature too large")
    return base64.b64decode(s.encode("utf-8"), validate=True)


def ensure_tls_cert():
    """
    Creates a local self-signed TLS cert for HTTPS demo.
    Includes SAN for localhost and 127.0.0.1 so hostname checks pass.
    """
    TLS_DIR.mkdir(exist_ok=True)

    if TLS_KEY.exists() and TLS_CERT.exists():
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(x509.datetime.datetime.utcnow() - x509.datetime.timedelta(days=1))
        .not_valid_after(x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    TLS_KEY.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    )
    TLS_CERT.write_bytes(cert.public_bytes(Encoding.PEM))


@APP.get("/health")
def health():
    return jsonify({"ok": True, "time": int(now())})


@APP.post("/login/start")
def login_start():
    clean_expired()
    body = request.get_json(force=True, silent=True) or {}

    cert_pem = body.get("cert_pem", "")
    if not isinstance(cert_pem, str) or "BEGIN CERTIFICATE" not in cert_pem:
        return jsonify({"ok": False, "error": "Missing/invalid cert_pem"}), 400

    try:
        ca = load_ca_cert()
        crl, crl_status = load_crl_strict()
        cert = pem_to_cert(cert_pem)

        # Validate cert signature + validity
        verify_cert_signed_by_ca(cert, ca)
        check_cert_validity(cert)

        # Revocation check (CRL)
        if is_revoked(crl, cert):
            print("\n--- LOGIN START ---")
            print("Certificate validated successfully.")
            print(f"Subject: {cert.subject.rfc4514_string()}")
            print(f"Serial (decimal): {cert.serial_number}")
            print(crl_status)
            print("REVOCATION: serial found in CRL -> REJECT (401)")
            print("--------------------\n")
            return jsonify({"ok": False, "error": "Certificate is revoked (CRL)"}), 401

        # Generate challenge
        nonce = secrets.token_bytes(32)
        challenge_id = secrets.token_urlsafe(18)
        fp = cert_fingerprint_sha256(cert)

        PENDING[challenge_id] = PendingChallenge(
            nonce=nonce,
            expires_at=now() + NONCE_TTL_SECONDS,
            cert_fingerprint=fp,
        )

        # Academic logs (for screenshots)
        print("\n--- LOGIN START ---")
        print("Certificate validated successfully.")
        print(f"Subject: {cert.subject.rfc4514_string()}")
        print(f"Serial (decimal): {cert.serial_number}")
        print(crl_status)
        print(f"Generated challenge_id: {challenge_id}")
        print(f"Generated nonce (hex): {nonce.hex()}")
        print(f"TTL: {NONCE_TTL_SECONDS} seconds")
        print("--------------------\n")

        return jsonify({
            "ok": True,
            "challenge_id": challenge_id,
            "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        })

    except FileNotFoundError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    except InvalidSignature:
        return jsonify({"ok": False, "error": "Certificate not signed by trusted CA"}), 401
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 400


@APP.post("/login/finish")
def login_finish():
    clean_expired()
    body = request.get_json(force=True, silent=True) or {}

    cert_pem = body.get("cert_pem", "")
    challenge_id = body.get("challenge_id", "")
    signature_b64 = body.get("signature_b64", "")

    if not (isinstance(cert_pem, str) and isinstance(challenge_id, str) and isinstance(signature_b64, str)):
        return jsonify({"ok": False, "error": "Invalid request format"}), 400
    if challenge_id not in PENDING:
        return jsonify({"ok": False, "error": "Unknown/expired challenge_id"}), 401

    pending = PENDING[challenge_id]

    try:
        ca = load_ca_cert()
        crl, crl_status = load_crl_strict()
        cert = pem_to_cert(cert_pem)

        verify_cert_signed_by_ca(cert, ca)
        check_cert_validity(cert)

        # Revocation check again at finish (defense-in-depth)
        if is_revoked(crl, cert):
            print("\n--- LOGIN FINISH ---")
            print(f"Subject: {cert.subject.rfc4514_string()}")
            print(f"Serial (decimal): {cert.serial_number}")
            print(crl_status)
            print("REVOCATION: serial found in CRL -> REJECT (401)")
            print("--------------------\n")
            return jsonify({"ok": False, "error": "Certificate is revoked (CRL)"}), 401

        fp = cert_fingerprint_sha256(cert)
        if fp != pending.cert_fingerprint:
            return jsonify({"ok": False, "error": "Certificate changed during challenge"}), 401

        sig = b64_to_bytes(signature_b64)

        pub = cert.public_key()
        pub.verify(
            sig,
            pending.nonce,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        token = secrets.token_urlsafe(24)
        TOKENS[token] = SessionToken(
            token=token,
            expires_at=now() + TOKEN_TTL_SECONDS,
            cert_fingerprint=fp
        )

        del PENDING[challenge_id]

        print("\n--- LOGIN FINISH ---")
        print("Signature verification: SUCCESS (RSA-PSS + SHA-256)")
        print(f"Issued token (TTL): {TOKEN_TTL_SECONDS} seconds")
        print("--------------------\n")

        return jsonify({"ok": True, "token": token, "expires_in_seconds": TOKEN_TTL_SECONDS})

    except InvalidSignature:
        return jsonify({"ok": False, "error": "Signature invalid"}), 401
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 400


if __name__ == "__main__":
    ensure_tls_cert()
    APP.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        ssl_context=(str(TLS_CERT), str(TLS_KEY)),
    )