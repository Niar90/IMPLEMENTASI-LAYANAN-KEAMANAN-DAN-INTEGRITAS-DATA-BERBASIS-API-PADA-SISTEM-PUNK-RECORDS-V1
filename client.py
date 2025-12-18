from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import base64, os, requests

SERVER = "http://127.0.0.1:8080"
USERS = ["nia", "nurul", "ais"]

KEY_DIR = "client_keys"
os.makedirs(KEY_DIR, exist_ok=True)

for USER in USERS:
    PRIV_PATH = f"{KEY_DIR}/{USER}_priv.pem"
    PUB_PATH = f"{KEY_DIR}/{USER}_pub.pem"

    # =========================
    # GENERATE / LOAD KEY
    # =========================
    if not os.path.exists(PRIV_PATH):
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        with open(PRIV_PATH, "wb") as f:
            f.write(priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        with open(PUB_PATH, "wb") as f:
            f.write(pub_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[{USER}] Key pair generated")
    else:
        with open(PRIV_PATH, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None)
        pub_key = priv_key.public_key()
        print(f"[{USER}] Key pair loaded")

    # =========================
    # GET TOKEN
    # =========================
    token = requests.post(f"{SERVER}/token?username={USER}").json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # =========================
    # UPLOAD PUBLIC KEY
    # =========================
    with open(PUB_PATH, "rb") as f:
        res = requests.post(f"{SERVER}/store?username={USER}", files={"file": f}, headers=headers)
    print(f"[{USER}] Public key uploaded: {res.json()['fingerprint']}")

    # =========================
    # RELAY MESSAGE
    # =========================
    message = f"Hello from {USER}"
    signature = priv_key.sign(message.encode())
    signature_b64 = base64.b64encode(signature).decode()
    print(f"[{USER}] Signature: {signature_b64}")

    for to_user in USERS:
        if to_user != USER:
            relay = requests.post(
                f"{SERVER}/relay",
                params={"to_user": to_user, "message": message, "signature": signature_b64},
                headers=headers
            )
            print(f"[{USER} → {to_user}] {relay.json()['message']}")

# =========================
# CHECK INBOX
# =========================
for USER in USERS:
    token = requests.post(f"{SERVER}/token?username={USER}").json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    inbox = requests.get(f"{SERVER}/inbox", headers=headers).json()
    print(f"\nInbox for {USER}:")
    for m in inbox:
        print(f"From: {m['from']}, Message: {m['message']}, Time: {m['time']}")

# CLIENT-SIDE PDF DIGITAL SIGNATURE
PDF_FILE = "portfolio.pdf"
PDF_USER = "nia"

priv_path = f"{KEY_DIR}/{PDF_USER}_priv.pem"

with open(priv_path, "rb") as f:
    priv_key = serialization.load_pem_private_key(f.read(), password=None)

with open(PDF_FILE, "rb") as f:
    pdf_bytes = f.read()

# hash pdf
digest = hashes.Hash(hashes.SHA256())
digest.update(pdf_bytes)
pdf_hash = digest.finalize()

pdf_hash_b64 = base64.b64encode(pdf_hash).decode()

# SIGN HASH (CLIENT SIDE)
pdf_signature = priv_key.sign(pdf_hash_b64.encode())
pdf_signature_b64 = base64.b64encode(pdf_signature).decode()

print("\nPDF DIGITAL SIGNATURE (CLIENT SIDE)")
print("User      :", PDF_USER)
print("PDF Hash  :", pdf_hash_b64)
print("Signature :", pdf_signature_b64)

# VERIFY SIGNATURE VIA SERVER
token = requests.post(f"{SERVER}/token?username={PDF_USER}").json()["token"]

verify = requests.post(
    f"{SERVER}/verify",
    params={
        "username": PDF_USER,
        "message": pdf_hash_b64,
        "signature": pdf_signature_b64
    },
    headers={"Authorization": f"Bearer {token}"}
)

print("\nSERVER VERIFICATION RESULT")
print(verify.json())
