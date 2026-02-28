from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

BASE = Path(__file__).resolve().parent
TLS_DIR = BASE / "tls"
TLS_DIR.mkdir(exist_ok=True)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo Org"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName("127.0.0.1"),
    ]), critical=False)
    .sign(key, hashes.SHA256())
)

(TLS_DIR / "server_key.pem").write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

(TLS_DIR / "server_cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print("[+] Created server/tls/server_cert.pem + server_key.pem")