# client/gui_app.py
from __future__ import annotations

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ===== Paths =====
BASE = Path(__file__).resolve().parent
ROOT = BASE.parent

USER_KEY = BASE / "user_key.pem"
USER_CSR = BASE / "user_csr.pem"
USER_CERT = BASE / "user_cert.pem"

DOCS_DIR = BASE / "documents"
SIG_DIR = BASE / "signatures"
ASSETS_DIR = BASE / "assets"
LOGO_PATH = ASSETS_DIR / "logo.png"

DOCS_DIR.mkdir(exist_ok=True)
SIG_DIR.mkdir(exist_ok=True)
ASSETS_DIR.mkdir(exist_ok=True)

# HTTPS server
SERVER = "https://localhost:5000"

# Trust the server's self-signed TLS certificate (better than disabling verification)
TLS_CERT = ROOT / "server" / "tls" / "server_cert.pem"
SSL_CTX = ssl.create_default_context(cafile=str(TLS_CERT))


# ===== Helpers =====
def ts() -> str:
    return time.strftime("%H:%M:%S")


def post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
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


def get_json(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=5, context=SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def safe_cert_summary(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = "(no CN)"
    return (
        f"Common Name (CN): {cn}\n"
        f"Serial: {cert.serial_number}\n"
        f"Valid from: {cert.not_valid_before_utc}\n"
        f"Valid until: {cert.not_valid_after_utc}\n"
        f"SHA256 Fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}\n"
    )


def load_private_key(passphrase: str):
    return serialization.load_pem_private_key(
        USER_KEY.read_bytes(),
        password=passphrase.encode("utf-8"),
    )


def sign_bytes(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def sign_file(file_path: Path, passphrase: str) -> Path:
    data = file_path.read_bytes()
    key = load_private_key(passphrase)
    sig = sign_bytes(key, data)
    sig_path = file_path.with_suffix(file_path.suffix + ".sig")
    sig_path.write_bytes(sig)
    return sig_path


def verify_file(file_path: Path, sig_path: Path, cert_path: Path) -> bool:
    data = file_path.read_bytes()
    sig = sig_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    pub = cert.public_key()
    try:
        pub.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ===== GUI =====
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PKI Passwordless Corporate Login")
        self.geometry("1180x720")
        self.minsize(1100, 680)

        self.token_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready ✅")
        self.server_status_var = tk.StringVar(value="Server: unknown")
        self.challenge_id: str | None = None

        self._style()
        self._layout()
        self._ping_server()

    # ---------- Styling ----------
    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Brand palette
        self.COLOR_BG = "#0b1220"
        self.COLOR_PANEL = "#111b2e"
        self.COLOR_CARD = "#0f172a"
        self.COLOR_SURFACE = "#0b1220"
        self.COLOR_TEXT = "#e5e7eb"
        self.COLOR_MUTED = "#94a3b8"
        self.COLOR_ACCENT = "#22c55e"   # green
        self.COLOR_PRIMARY = "#3b82f6"  # blue
        self.COLOR_WARN = "#f59e0b"     # amber
        self.COLOR_DANGER = "#ef4444"   # red

        self.configure(bg=self.COLOR_BG)

        style.configure("Header.TFrame", background=self.COLOR_PANEL)
        style.configure("HeaderTitle.TLabel", background=self.COLOR_PANEL, foreground="white", font=("Segoe UI", 18, "bold"))
        style.configure("HeaderSub.TLabel", background=self.COLOR_PANEL, foreground=self.COLOR_MUTED, font=("Segoe UI", 10))

        style.configure("Main.TFrame", background=self.COLOR_BG)

        style.configure("Card.TFrame", background=self.COLOR_CARD)
        style.configure("CardTitle.TLabel", background=self.COLOR_CARD, foreground="white", font=("Segoe UI", 13, "bold"))
        style.configure("Body.TLabel", background=self.COLOR_CARD, foreground=self.COLOR_TEXT, font=("Segoe UI", 10))
        style.configure("Small.TLabel", background=self.COLOR_CARD, foreground=self.COLOR_MUTED, font=("Segoe UI", 9))

        style.configure("Tab.TFrame", background=self.COLOR_BG)

        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=10)
        style.configure("Ghost.TButton", font=("Segoe UI", 10), padding=10)

        style.map("Primary.TButton", background=[("active", self.COLOR_PRIMARY)])
        style.map("Ghost.TButton", background=[("active", "#1f2a44")])

        # Notebook styling
        style.configure("TNotebook", background=self.COLOR_BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 8), background="#1f2a44", foreground="white")
        style.map("TNotebook.Tab", background=[("selected", self.COLOR_PRIMARY)], foreground=[("selected", "white")])

    # ---------- Layout ----------
    def _layout(self):
        # Header (brand)
        header = ttk.Frame(self, style="Header.TFrame", padding=(18, 14))
        header.pack(fill="x")

        left = ttk.Frame(header, style="Header.TFrame")
        left.pack(side="left", fill="x", expand=True)

        ttk.Label(left, text="PKI Secure Access Portal", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(
            left,
            text="Enroll → CA issues certificate → Passwordless login (nonce-sign) → Token → Sign/Verify documents",
            style="HeaderSub.TLabel",
        ).pack(anchor="w", pady=(6, 0))

        right = ttk.Frame(header, style="Header.TFrame")
        right.pack(side="right")

        ttk.Label(right, text="Support: +977-9898064622", style="HeaderSub.TLabel").pack(anchor="e")
        ttk.Label(right, text="Environment: (Localhost TLS)", style="HeaderSub.TLabel").pack(anchor="e", pady=(4, 0))

        # Main split
        main = ttk.Frame(self, style="Main.TFrame", padding=14)
        main.pack(fill="both", expand=True)

        main.columnconfigure(0, weight=3)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=1)

        # Left: Tabs area
        left_panel = ttk.Frame(main, style="Main.TFrame")
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        left_panel.rowconfigure(0, weight=1)
        left_panel.columnconfigure(0, weight=1)

        notebook = ttk.Notebook(left_panel)
        notebook.grid(row=0, column=0, sticky="nsew")

        self.tab_enroll = ttk.Frame(notebook, padding=14, style="Tab.TFrame")
        self.tab_login = ttk.Frame(notebook, padding=14, style="Tab.TFrame")
        self.tab_sign = ttk.Frame(notebook, padding=14, style="Tab.TFrame")

        notebook.add(self.tab_enroll, text="1) Enroll")
        notebook.add(self.tab_login, text="2) Login")
        notebook.add(self.tab_sign, text="3) Sign / Verify")

        self._build_enroll_tab()
        self._build_login_tab()
        self._build_sign_tab()

        # Right: Log + status
        right_panel = ttk.Frame(main, style="Card.TFrame", padding=14)
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.rowconfigure(3, weight=1)
        right_panel.columnconfigure(0, weight=1)

        # Logo row
        logo_row = ttk.Frame(right_panel, style="Card.TFrame")
        logo_row.grid(row=0, column=0, sticky="ew")

        ttk.Label(logo_row, text="Activity & Security", style="CardTitle.TLabel").pack(side="left")

        # Optional logo
        self._logo_img = None
        if LOGO_PATH.exists():
            try:
                self._logo_img = tk.PhotoImage(file=str(LOGO_PATH))
                ttk.Label(logo_row, image=self._logo_img, background=self.COLOR_CARD).pack(side="right")
            except Exception:
                pass

        self.server_lbl = ttk.Label(right_panel, textvariable=self.server_status_var, style="Small.TLabel")
        self.server_lbl.grid(row=1, column=0, sticky="w", pady=(8, 8))

        sec_box = ttk.Frame(right_panel, style="Card.TFrame")
        sec_box.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(sec_box, text="Security Status", style="Body.TLabel").pack(anchor="w")
        ttk.Label(
            sec_box,
            text="• Transport: HTTPS (TLS)\n• Server TLS cert pinned (cafile)\n• Login: Nonce signed with private key\n• Server verifies via CA trust + CRL",
            style="Small.TLabel",
            justify="left"
        ).pack(anchor="w", pady=(6, 0))

        self.log = tk.Text(
            right_panel,
            height=22,
            bg="#050a14",
            fg="#e5e7eb",
            insertbackground="#e5e7eb",
            relief="solid",
            bd=1,
        )
        self.log.grid(row=3, column=0, sticky="nsew")
        self.log.insert("end", f"[{ts()}] Ready ✅\n")
        self.log.insert("end", f"[{ts()}] Start server: python server\\server.py\n")
        self.log.insert("end", f"[{ts()}] URL: {SERVER}\n")
        self.log.configure(state="disabled")

        # Footer
        footer = ttk.Frame(self, style="Main.TFrame", padding=(14, 10))
        footer.pack(fill="x")
        ttk.Label(
            footer,
            textvariable=self.status_var,
            background=self.COLOR_BG,
            foreground="white",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")

    # ---------- Components ----------
    def _card(self, parent, title: str, subtitle: str = "") -> ttk.Frame:
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        card.pack(fill="x", pady=(0, 12))
        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(card, text=subtitle, style="Small.TLabel").pack(anchor="w", pady=(6, 0))
        return card

    def _log(self, msg: str):
        self.log.configure(state="normal")
        self.log.insert("end", f"[{ts()}] {msg}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _ping_server(self):
        r = get_json(f"{SERVER}/health")
        if r.get("ok"):
            self.server_status_var.set(f"Server: Online ✅  ({SERVER})")
        else:
            self.server_status_var.set("Server: Offline ❌  (start: python server\\server.py)")
        self.after(2500, self._ping_server)

    # ---------- Enroll ----------
    def _build_enroll_tab(self):
        card = self._card(
            self.tab_enroll,
            "Create New User (Encrypted Key + CSR)",
            "Generates an encrypted private key and CSR (certificate request). Passphrase never leaves the client.",
        )

        form = ttk.Frame(card, style="Card.TFrame")
        form.pack(fill="x", pady=(10, 0))
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Username (CN)", style="Body.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=6)
        self.enroll_user = tk.StringVar(value="test")
        ttk.Entry(form, textvariable=self.enroll_user).grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Passphrase (encrypt private key)", style="Body.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=6)
        self.enroll_pass = tk.StringVar(value="")
        ttk.Entry(form, textvariable=self.enroll_pass, show="•").grid(row=1, column=1, sticky="ew", pady=6)

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill="x", pady=(12, 0))

        ttk.Button(btns, text="Generate Key + CSR", style="Primary.TButton", command=self.do_enroll).pack(side="left")
        ttk.Button(btns, text="Open client folder", style="Ghost.TButton", command=self.open_client_folder).pack(side="left", padx=10)
        ttk.Button(btns, text="Show certificate info", style="Ghost.TButton", command=self.show_cert_info).pack(side="left")

        tip = self._card(
            self.tab_enroll,
            "Next Step (CA Issues Certificate)",
            "Use the CA tool to issue a certificate, then copy it into client/user_cert.pem",
        )
        tip_text = (
            "1) Issue certificate (Terminal):\n"
            "   python ca\\ca_issue.py\n"
            "   CSR path: client\\user_csr.pem\n"
            "   Output : ca\\issued\\<name>_cert.pem\n\n"
            "2) Copy issued cert to:\n"
            "   client\\user_cert.pem\n"
        )
        ttk.Label(tip, text=tip_text, style="Body.TLabel", justify="left").pack(anchor="w", pady=(8, 0))

    def open_client_folder(self):
        try:
            os.startfile(str(BASE))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_enroll(self):
        username = self.enroll_user.get().strip()
        passphrase = self.enroll_pass.get().strip()

        if len(username) < 2:
            self.status_var.set("Username must be at least 2 characters.")
            return
        if len(passphrase) < 6:
            self.status_var.set("Passphrase must be at least 6 characters.")
            return

        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        enc = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        USER_KEY.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc,
            )
        )

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
        USER_CSR.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        self._log(f"Enroll OK: user_key.pem + user_csr.pem created (CN={username})")
        self.status_var.set("Enroll complete ✅ Now issue cert in CA and copy into client/user_cert.pem")

    def show_cert_info(self):
        if not USER_CERT.exists():
            messagebox.showwarning("No certificate", "client\\user_cert.pem not found. Issue and copy certificate first.")
            return
        try:
            info = safe_cert_summary(USER_CERT.read_text("utf-8"))
            messagebox.showinfo("Certificate Info", info)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------- Login ----------
    def _build_login_tab(self):
        card = self._card(
            self.tab_login,
            "Passwordless Login (Nonce → Sign → Verify)",
            "Server sends a random challenge. Client signs using private key. Server verifies using CA-trusted certificate + CRL.",
        )

        form = ttk.Frame(card, style="Card.TFrame")
        form.pack(fill="x", pady=(10, 0))
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Passphrase (unlock private key)", style="Body.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=6)
        self.login_pass = tk.StringVar(value="")
        ttk.Entry(form, textvariable=self.login_pass, show="•").grid(row=0, column=1, sticky="ew", pady=6)

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="Login", style="Primary.TButton", command=self.do_login).pack(side="left")
        ttk.Button(btns, text="Copy token", style="Ghost.TButton", command=self.copy_token).pack(side="left", padx=10)
        ttk.Button(btns, text="Clear", style="Ghost.TButton", command=self.clear_token).pack(side="left")

        token_card = self._card(self.tab_login, "Session Token", "Returned only after signature verification succeeds.")
        self.token_entry = ttk.Entry(token_card, textvariable=self.token_var)
        self.token_entry.pack(fill="x", pady=(10, 0))

    def clear_token(self):
        self.token_var.set("")
        self.status_var.set("Cleared.")
        self._log("Token cleared.")

    def copy_token(self):
        token = self.token_var.get().strip()
        if not token:
            return
        self.clipboard_clear()
        self.clipboard_append(token)
        self.status_var.set("Token copied ✅")
        self._log("Token copied to clipboard.")

    def do_login(self):
        if not USER_KEY.exists():
            messagebox.showerror("Missing key", "client\\user_key.pem not found. Enroll first.")
            return
        if not USER_CERT.exists():
            messagebox.showerror("Missing cert", "client\\user_cert.pem not found. Issue cert and copy it first.")
            return

        passphrase = self.login_pass.get().strip()
        if len(passphrase) < 6:
            self.status_var.set("Passphrase too short.")
            return

        cert_pem = USER_CERT.read_text("utf-8")

        start = post_json(f"{SERVER}/login/start", {"cert_pem": cert_pem})
        if not start.get("ok"):
            self.status_var.set("Login start failed ❌")
            self._log(f"Login start failed: {start}")
            messagebox.showerror("Login start failed", start.get("error", "Unknown error"))
            return

        self.challenge_id = start["challenge_id"]
        nonce = base64.b64decode(start["nonce_b64"].encode("utf-8"))

        try:
            key = load_private_key(passphrase)
            sig = sign_bytes(key, nonce)
            sig_b64 = base64.b64encode(sig).decode("utf-8")
        except Exception as e:
            self._log(f"Key unlock/sign failed: {e}")
            messagebox.showerror("Key error", f"Could not unlock key / sign nonce:\n{e}")
            return

        finish = post_json(
            f"{SERVER}/login/finish",
            {"cert_pem": cert_pem, "challenge_id": self.challenge_id, "signature_b64": sig_b64},
        )

        if not finish.get("ok"):
            self.status_var.set("Login failed ❌")
            self._log(f"Login failed: {finish}")
            messagebox.showerror("Login failed", finish.get("error", "Unknown error"))
            return

        token = finish["token"]
        self.token_var.set(token)
        self.status_var.set("LOGIN SUCCESS ✅")
        self._log("LOGIN SUCCESS ✅ Token issued.")

    # ---------- Sign / Verify ----------
    def _build_sign_tab(self):
        card = self._card(
            self.tab_sign,
            "Digital Signatures (Integrity)",
            "Sign a file using your private key. Verify using the public key inside your certificate.",
        )

        grid = ttk.Frame(card, style="Card.TFrame")
        grid.pack(fill="x", pady=(10, 0))
        grid.columnconfigure(1, weight=1)

        self.doc_path = tk.StringVar(value=str(DOCS_DIR / "msg.txt"))
        self.sig_path = tk.StringVar(value="")

        ttk.Label(grid, text="Document file", style="Body.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(grid, textvariable=self.doc_path).grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Button(grid, text="Browse", style="Ghost.TButton", command=self.browse_doc).grid(row=0, column=2, padx=8)

        ttk.Label(grid, text="Signature file", style="Body.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(grid, textvariable=self.sig_path).grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Button(grid, text="Browse", style="Ghost.TButton", command=self.browse_sig).grid(row=1, column=2, padx=8)

        ttk.Label(grid, text="Passphrase (unlock key)", style="Body.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=6)
        self.sign_pass = tk.StringVar(value="")
        ttk.Entry(grid, textvariable=self.sign_pass, show="•").grid(row=2, column=1, sticky="ew", pady=6)

        btns = ttk.Frame(card, style="Card.TFrame")
        btns.pack(fill="x", pady=(12, 0))

        ttk.Button(btns, text="Sign document", style="Primary.TButton", command=self.do_sign).pack(side="left")
        ttk.Button(btns, text="Verify signature", style="Ghost.TButton", command=self.do_verify).pack(side="left", padx=10)
        ttk.Button(btns, text="Create demo msg.txt", style="Ghost.TButton", command=self.create_demo_file).pack(side="left")

        tip = self._card(self.tab_sign, "Tip", "Show VALID then tamper file and show INVALID")
        tip_text = (
            "1) Create/open msg.txt\n"
            "2) Sign → creates msg.txt.sig\n"
            "3) Verify → VALID ✅\n"
            "4) Edit msg.txt → Verify → INVALID ❌\n"
        )
        ttk.Label(tip, text=tip_text, style="Body.TLabel", justify="left").pack(anchor="w", pady=(8, 0))

    def browse_doc(self):
        p = filedialog.askopenfilename(initialdir=str(DOCS_DIR), title="Select document")
        if p:
            self.doc_path.set(p)

    def browse_sig(self):
        p = filedialog.askopenfilename(initialdir=str(DOCS_DIR), title="Select signature")
        if p:
            self.sig_path.set(p)

    def create_demo_file(self):
        p = Path(self.doc_path.get().strip())
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("This is a message for digital signature integrity check.\n", encoding="utf-8")
        try:
            os.startfile(str(p))
        except Exception:
            pass
        self._log(f"File ready: {p}")
        self.status_var.set("File created/opened ✅")

    def do_sign(self):
        if not USER_KEY.exists():
            messagebox.showerror("Missing key", "client\\user_key.pem not found. Enroll first.")
            return

        file_in = self.doc_path.get().strip()
        if not file_in:
            return

        passphrase = self.sign_pass.get().strip()
        if len(passphrase) < 6:
            messagebox.showwarning("Passphrase", "Enter the same passphrase used during enrollment.")
            return

        try:
            file_path = Path(file_in)
            if not file_path.exists():
                messagebox.showerror("File missing", f"Document not found:\n{file_path}")
                return

            sig_path = sign_file(file_path, passphrase)
            self.sig_path.set(str(sig_path))
            self._log(f"Signed: {file_path.name} → {sig_path.name}")
            self.status_var.set("Signed successfully ✅")
        except Exception as e:
            self._log(f"Sign error: {e}")
            messagebox.showerror("Sign failed", str(e))

    def do_verify(self):
        if not USER_CERT.exists():
            messagebox.showerror("Missing cert", "client\\user_cert.pem not found. Issue and copy certificate first.")
            return

        file_in = self.doc_path.get().strip()
        sig_in = self.sig_path.get().strip()

        if not file_in or not sig_in:
            messagebox.showwarning("Missing input", "Select document + signature file.")
            return

        try:
            ok = verify_file(Path(file_in), Path(sig_in), USER_CERT)
            if ok:
                self._log("VERIFY: VALID ✅")
                self.status_var.set("VALID ✅")
                messagebox.showinfo("Verify", "VALID ✅\nSignature matches the document.")
            else:
                self._log("VERIFY: INVALID ❌")
                self.status_var.set("INVALID ❌")
                messagebox.showwarning("Verify", "INVALID ❌\nDocument changed (tampered) or wrong signature.")
        except Exception as e:
            self._log(f"Verify error: {e}")
            messagebox.showerror("Verify failed", str(e))


if __name__ == "__main__":
    App().mainloop()