from pathlib import Path
import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

BASE = Path(__file__).resolve().parent
USER_CERT = BASE / "user_cert.pem"

def verify_file(file_path: Path, sig_path: Path) -> bool:
    data = file_path.read_bytes()
    sig = base64.b64decode(sig_path.read_text().strip())

    cert = x509.load_pem_x509_certificate(USER_CERT.read_bytes())
    public_key = cert.public_key()

    try:
        public_key.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def main():
    file_in = input("File to verify (e.g., client\\documents\\msg.txt): ").strip()
    sig_in = input("Signature file (e.g., client\\documents\\msg.txt.sig): ").strip()

    ok = verify_file(Path(file_in), Path(sig_in))
    print("[+] VALID ✅" if ok else "[!] INVALID ❌ (tampered or wrong signature)")

if __name__ == "__main__":
    main()
