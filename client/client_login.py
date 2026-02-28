# client/client_login.py
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent

USER_KEY = BASE / "user_key.pem"
USER_CERT = BASE / "user_cert.pem"

# Use HTTPS
SERVER = "https://localhost:5000"

# For demo: trust the self-signed TLS cert created by the server
# (More secure than disabling verification.)
TLS_CERT = ROOT / "server" / "tls" / "server_cert.pem"
SSL_CTX = ssl.create_default_context(cafile=str(TLS_CERT))


def post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")
        try:
            return json.loads(body)
        except Exception:
            return {"ok": False, "error": f"HTTP {e.code}: {body or e.reason}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def main():
    passphrase = input("Enter private-key passphrase: ").strip()
    key = serialization.load_pem_private_key(USER_KEY.read_bytes(), password=passphrase.encode("utf-8"))

    cert_pem_text = USER_CERT.read_text(encoding="utf-8")

    start = post_json(f"{SERVER}/login/start", {"cert_pem": cert_pem_text})
    if not start.get("ok"):
        print("[!] Start failed:", start)
        return

    challenge_id = start["challenge_id"]
    nonce = base64.b64decode(start["nonce_b64"])

    signature = key.sign(
        nonce,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    finish = post_json(
        f"{SERVER}/login/finish",
        {
            "cert_pem": cert_pem_text,
            "challenge_id": challenge_id,
            "signature_b64": base64.b64encode(signature).decode("utf-8"),
        },
    )

    if finish.get("ok"):
        print("[+] LOGIN SUCCESS ✅")
        print("Token:", finish["token"])
    else:
        print("[!] LOGIN FAILED ❌")
        print(finish)


if __name__ == "__main__":
    main()