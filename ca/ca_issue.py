# ca/ca_issue.py
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

BASE = Path(__file__).resolve().parent
CA_KEY_PATH = BASE / "ca_key.pem"
CA_CERT_PATH = BASE / "ca_cert.pem"
ISSUED_DIR = BASE / "issued"

def main():
    ISSUED_DIR.mkdir(parents=True, exist_ok=True)

    csr_path = input("CSR path (e.g., client\\user_csr.pem): ").strip()
    out_path = input("Output cert path (e.g., ca\\issued\\alice_cert.pem): ").strip()

    csr_file = Path(csr_path)
    out_file = Path(out_path)

    ca_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    csr = x509.load_pem_x509_csr(csr_file.read_bytes())

    if not csr.is_signature_valid:
        raise SystemExit("CSR signature invalid.")

    now = datetime.now(timezone.utc)

    user_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_bytes(user_cert.public_bytes(serialization.Encoding.PEM))

    print("[+] Certificate issued:", out_file)
    print("    Serial (decimal):", user_cert.serial_number)

if __name__ == "__main__":
    main()
