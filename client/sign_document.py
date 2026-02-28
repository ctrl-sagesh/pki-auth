from pathlib import Path
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE = Path(__file__).resolve().parent
USER_KEY = BASE / "user_key.pem"

def sign_file(file_path: Path, passphrase: str) -> bytes:
    data = file_path.read_bytes()

    private_key = serialization.load_pem_private_key(
        USER_KEY.read_bytes(),
        password=passphrase.encode()
    )

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def main():
    file_in = input("File to sign (e.g., client\\documents\\msg.txt): ").strip()
    passphrase = input("Private key passphrase: ").strip()

    sig = sign_file(Path(file_in), passphrase)
    out_path = Path(file_in + ".sig")

    out_path.write_text(base64.b64encode(sig).decode())
    print(f"[+] Signed successfully")
    print(f"    Signature saved to: {out_path}")

if __name__ == "__main__":
    main()
