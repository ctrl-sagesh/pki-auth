# PKI Passwordless Authentication System

A complete Public Key Infrastructure (PKI) system implementing:
- Certificate Authority (CA) with issuance and revocation
- Flask HTTPS authentication server with challenge-response login
- Tkinter GUI client with enrollment, login, signing, and verification

## Module
ST6051CEM — Practical Cryptography | Coventry University

## Technologies
- Python 3.12
- cryptography library (RSA-2048, RSA-PSS, X.509, CRL)
- Flask (HTTPS server)
- Tkinter (GUI)
- TLS 1.2+

## Project Structure
pki-auth/
├── ca/                    # Certificate Authority
│   ├── ca_init.py         # Generate root CA key + self-signed cert
│   ├── ca_issue.py        # Issue user certificates from CSR
│   ├── ca_revoke.py       # Revoke certs and generate CRL
│   ├── ca_cert.pem        # Root CA certificate
│   ├── issued/            # Issued user certificates
│   └── revoked.json       # Revocation serial database
├── client/                # Client Application
│   ├── gui_app.py         # Tkinter GUI (Enroll, Login, Sign, Verify)
│   ├── client_enroll.py   # RSA key gen + CSR creation
│   ├── client_login.py    # HTTPS challenge-response login
│   ├── sign_document.py   # RSA-PSS document signing
│   └── verify_document.py # Signature verification
└── server/                # Authentication Server
    ├── server.py          # Flask HTTPS server (login/start, login/finish)
    ├── trusted_ca.pem     # Copy of CA cert (trust anchor)
    └── tls/               # Server TLS certificate

## How to Run

### 1. Initialize the CA (first time only)
cd ca
python ca_init.py

2. Start the Server
cd server
python server.py

3. Launch the GUI Client
cd client
python gui_app.py

4. Enroll → Issue → Copy cert → Login

Enter username and passphrase in the Enroll tab, click Generate
Run python ca/ca_issue.py in a separate terminal, enter CSR and output paths
Copy the issued cert to client/user_cert.pem
Go to Login tab, enter passphrase, click Login

Security Features
RSA-2048 with RSA-PSS + SHA-256 signatures
TLS encrypted communication
Nonce-based replay attack prevention
CRL-based certificate revocation support

Author
Sagesh Adhikari | 14806504_230298 | 
