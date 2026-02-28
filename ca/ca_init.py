# ca/ca_init.py
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BASE = Path(__file__).resolve().parent
CA_KEY_PATH = BASE / "ca_key.pem"
CA_CERT_PATH = BASE / "ca_cert.pem"

ORG = "SKYsoft"
CA_COMMON_NAME = "SKYsoft Root CA"
VALID_DAYS = 3650  # 10 years


def main():
    BASE.mkdir(parents=True, exist_ok=True)

    if CA_KEY_PATH.exists() or CA_CERT_PATH.exists():
        raise SystemExit("CA already exists. Delete ca_key.pem/ca_cert.pem to regenerate.")

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kathmandu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
    ])

    now = datetime.now(timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("[+] Root CA created successfully")
    print(f"    Key : {CA_KEY_PATH}")
    print(f"    Cert: {CA_CERT_PATH}")


if __name__ == "__main__":
    main()
