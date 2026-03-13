import os
import base64
import hashlib
from cryptography.fernet import Fernet

from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt, decrypt
from pqcrypto.sign.ml_dsa_44 import generate_keypair as sign_keypair
from pqcrypto.sign.ml_dsa_44 import sign, verify

BASE = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

ENC_FOLDER = os.path.join(BASE, "encrypted_storage")
DEC_FOLDER = os.path.join(BASE, "decrypted_storage")

os.makedirs(ENC_FOLDER, exist_ok=True)
os.makedirs(DEC_FOLDER, exist_ok=True)

# -----------------------------
# KYBER (ML-KEM) KEYS
# -----------------------------
KYBER_PUBLIC = os.path.join(BASE, "kyber_public.key")
KYBER_PRIVATE = os.path.join(BASE, "kyber_private.key")

if os.path.exists(KYBER_PUBLIC) and os.path.exists(KYBER_PRIVATE):
    with open(KYBER_PUBLIC, "rb") as f:
        kyber_public = f.read()
    with open(KYBER_PRIVATE, "rb") as f:
        kyber_private = f.read()
else:
    kyber_public, kyber_private = generate_keypair()
    with open(KYBER_PUBLIC, "wb") as f:
        f.write(kyber_public)
    with open(KYBER_PRIVATE, "wb") as f:
        f.write(kyber_private)

# -----------------------------
# DILITHIUM (ML-DSA) KEYS
# -----------------------------
DILITHIUM_PUBLIC = os.path.join(BASE, "dilithium_public.key")
DILITHIUM_PRIVATE = os.path.join(BASE, "dilithium_private.key")

if os.path.exists(DILITHIUM_PUBLIC) and os.path.exists(DILITHIUM_PRIVATE):
    with open(DILITHIUM_PUBLIC, "rb") as f:
        dilithium_public = f.read()
    with open(DILITHIUM_PRIVATE, "rb") as f:
        dilithium_private = f.read()
else:
    dilithium_public, dilithium_private = sign_keypair()
    with open(DILITHIUM_PUBLIC, "wb") as f:
        f.write(dilithium_public)
    with open(DILITHIUM_PRIVATE, "wb") as f:
        f.write(dilithium_private)


def derive_fernet_key(shared_secret: bytes) -> bytes:
    digest = hashlib.sha256(shared_secret).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_file(file):
    data = file.read()

    if not data:
        raise ValueError("Uploaded file is empty.")

    if not getattr(file, "filename", ""):
        raise ValueError("Invalid file name.")

    # ML-KEM encapsulation
    ciphertext, shared_secret = encrypt(kyber_public)

    fernet_key = derive_fernet_key(shared_secret)
    cipher = Fernet(fernet_key)
    encrypted_data = cipher.encrypt(data)

    enc_path = os.path.join(ENC_FOLDER, file.filename + ".enc")
    ct_path = enc_path + ".ct"
    sig_path = enc_path + ".sig"

    with open(enc_path, "wb") as f:
        f.write(encrypted_data)

    with open(ct_path, "wb") as f:
        f.write(ciphertext)

    signature = sign(dilithium_private, encrypted_data)

    with open(sig_path, "wb") as f:
        f.write(signature)

    return enc_path


def decrypt_file(path):
    ct_path = path + ".ct"
    sig_path = path + ".sig"

    if not os.path.exists(path):
        raise FileNotFoundError("Encrypted file not found.")

    if not os.path.exists(ct_path):
        raise FileNotFoundError("Kyber ciphertext missing.")

    if not os.path.exists(sig_path):
        raise FileNotFoundError("Signature missing.")

    with open(path, "rb") as f:
        encrypted_data = f.read()

    with open(sig_path, "rb") as f:
        signature = f.read()

    try:
        verify(dilithium_public, encrypted_data, signature)
    except Exception:
        raise ValueError("Integrity Check Failed - File Tampered")

    with open(ct_path, "rb") as f:
        ciphertext = f.read()

    try:
        # Correct order: decrypt(secret_key, ciphertext)
        shared_secret = decrypt(kyber_private, ciphertext)
    except Exception:
        raise ValueError("Kyber decryption failed")

    fernet_key = derive_fernet_key(shared_secret)
    cipher = Fernet(fernet_key)

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception:
        raise ValueError("File decryption failed")

    filename = os.path.basename(path).replace(".enc", "")
    output = os.path.join(DEC_FOLDER, filename)

    with open(output, "wb") as f:
        f.write(decrypted_data)

    return output