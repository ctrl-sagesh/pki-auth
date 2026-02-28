# client/client_enroll.py
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BASE = Path(__file__).resolve().parent
USER_KEY = BASE / "user_key.pem"
USER_CSR = BASE / "user_csr.pem"

def main():
    username = input("Username (e.g., alice): ").strip()
    if not username:
        raise SystemExit("Username required.")

    passphrase = input("Passphrase to encrypt private key: ").strip()
    if len(passphrase) < 6:
        raise SystemExit("Use at least 6 characters passphrase.")

    # 1) generate keypair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2) build CSR
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SKYsoft"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )

    # 3) save encrypted private key
    USER_KEY.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
        )
    )

    # 4) save CSR
    USER_CSR.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    print("[+] Enrollment complete")
    print("    Private key:", USER_KEY)
    print("    CSR       :", USER_CSR)
    print("[i] Next: send CSR to CA to issue certificate.")

if __name__ == "__main__":
    main()
