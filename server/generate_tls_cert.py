# server/generate_tls_cert.py

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from pathlib import Path

# Create tls folder if not exists
BASE = Path(__file__).resolve().parent
TLS_DIR = BASE / "tls"
TLS_DIR.mkdir(exist_ok=True)

KEY_PATH = TLS_DIR / "server_key.pem"
CERT_PATH = TLS_DIR / "server_cert.pem"

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Build self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    )
    .sign(private_key, hashes.SHA256())
)

# Write private key
KEY_PATH.write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

# Write certificate
CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

print("TLS certificate generated successfully!")
print(f"Key:  {KEY_PATH}")
print(f"Cert: {CERT_PATH}")
