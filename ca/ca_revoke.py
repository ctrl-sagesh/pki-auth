# ca/ca_revoke.py
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

BASE = Path(__file__).resolve().parent
CA_KEY = BASE / "ca_key.pem"
CA_CERT = BASE / "ca_cert.pem"
REVOKED_DB = BASE / "revoked.json"
CRL_OUT = BASE / "crl.pem"


def load_db():
    if not REVOKED_DB.exists():
        return {"revoked_serials": []}
    return json.loads(REVOKED_DB.read_text(encoding="utf-8"))


def save_db(db):
    REVOKED_DB.write_text(json.dumps(db, indent=2) + "\n", encoding="utf-8")


def main():
    serial_str = input("Enter cert serial to revoke (decimal): ").strip()
    serial = int(serial_str)

    db = load_db()
    if serial not in db["revoked_serials"]:
        db["revoked_serials"].append(serial)
        save_db(db)

    ca_key = serialization.load_pem_private_key(CA_KEY.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=7))
    )

    for s in db["revoked_serials"]:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(s))
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    CRL_OUT.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    print("[+] CRL generated:", CRL_OUT)
    print("[+] Revoked serials:", db["revoked_serials"])


if __name__ == "__main__":
    main()
