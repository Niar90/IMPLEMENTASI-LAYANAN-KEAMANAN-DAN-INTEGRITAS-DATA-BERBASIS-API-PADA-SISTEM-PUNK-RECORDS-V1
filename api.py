from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta
import os, base64, hashlib, jwt

# CONFIG
SECRET_KEY = "KID-UAS-SECRET"
TOKEN_EXPIRE_MIN = 30
ALLOWED_USERS = ["nia", "ais", "nurul"]
DATA_DIR = "data"
KEY_DIR = os.path.join(DATA_DIR, "pubkeys")
MSG_DIR = os.path.join(DATA_DIR, "inbox")
PDF_SIG_DIR = os.path.join(DATA_DIR, "pdf_signatures")
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(MSG_DIR, exist_ok=True)
os.makedirs(PDF_SIG_DIR, exist_ok=True)

app = FastAPI(title="Security Service")

security = HTTPBearer()

# JWT UTIL
def create_token(username: str):
    payload = {"user": username, "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MIN)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(cred: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(cred.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload["user"]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# STORE PUBLIC KEY
@app.post("/store")
async def store_pubkey(
    username: str,
    file: UploadFile = File(...),
    session_user: str = Depends(verify_token)
):
    if username != session_user:
        raise HTTPException(403, "Unauthorized")
    if username not in ALLOWED_USERS:
        raise HTTPException(403, "User not allowed")
    
    key_bytes = await file.read()
    # Validity check
    serialization.load_pem_public_key(key_bytes)
    fingerprint = hashlib.sha256(key_bytes).hexdigest()
    with open(os.path.join(KEY_DIR, f"{username}.pem"), "wb") as f:
        f.write(key_bytes)
    return {"message": "Public key stored", "fingerprint": fingerprint}

# GET TOKEN
@app.post("/token")
def get_token(username: str):
    if username not in ALLOWED_USERS:
        raise HTTPException(403, "User not allowed")
    return {"token": create_token(username)}

# VERIFY SIGNATURE
@app.post("/verify")
def verify_signature(username: str, message: str, signature: str, session_user: str = Depends(verify_token)):
    if username != session_user:
        raise HTTPException(403, "Session mismatch")
    pub_path = os.path.join(KEY_DIR, f"{username}.pem")
    if not os.path.exists(pub_path):
        raise HTTPException(404, "Public key not registered")
    with open(pub_path, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())
    try:
        pubkey.verify(base64.b64decode(signature), message.encode())
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}

# RELAY MESSAGE
@app.post("/relay")
def relay_message(to_user: str, message: str, signature: str, session_user: str = Depends(verify_token)):
    if to_user not in ALLOWED_USERS:
        raise HTTPException(404, "Receiver not found")
    pub_path = os.path.join(KEY_DIR, f"{session_user}.pem")
    if not os.path.exists(pub_path):
        raise HTTPException(404, "Sender public key not registered")
    with open(pub_path, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())
    pubkey.verify(base64.b64decode(signature), message.encode())

    # Save message to receiver inbox
    inbox_file = os.path.join(MSG_DIR, f"{to_user}.txt")
    with open(inbox_file, "a") as f:
        f.write(f"{datetime.now().isoformat()}|{session_user}|{message}\n")
    return {"message": f"Message relayed from {session_user} to {to_user}"}

# READ INBOX
@app.get("/inbox")
def read_inbox(session_user: str = Depends(verify_token)):
    inbox_file = os.path.join(MSG_DIR, f"{session_user}.txt")
    messages = []
    if os.path.exists(inbox_file):
        with open(inbox_file) as f:
            for line in f:
                ts, frm, msg = line.strip().split("|")
                messages.append({"time": ts, "from": frm, "message": msg})
    return messages

# SIGN PDF
# @app.post("/sign_pdf")
# async def sign_pdf(
#     username: str,
#     file: UploadFile = File(...),
#     session_user: str = Depends(verify_token)
# ):
#     if username != session_user:
#         raise HTTPException(403, "Unauthorized")
#     priv_path = os.path.join(DATA_DIR, f"{username}_priv.pem")
#     if not os.path.exists(priv_path):
#         raise HTTPException(404, "Private key not found")
#     with open(priv_path, "rb") as f:
#         privkey = serialization.load_pem_private_key(f.read(), password=None)
#     pdf_bytes = await file.read()
#     signature = privkey.sign(pdf_bytes)
#     sig_b64 = base64.b64encode(signature).decode()
#     sig_file = os.path.join(PDF_SIG_DIR, f"{username}_{file.filename}.sig")
#     with open(sig_file, "w") as f:
#         f.write(sig_b64)
#     return {"message": "PDF signed", "signature": sig_b64, "filename": file.filename}
