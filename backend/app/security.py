# Encryption, signatures, canaries

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

# --- Symmetric Encryption (AES-GCM) ---

def _derive_key(passphrase: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return PBKDF2(passphrase, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

def encrypt_message(plaintext: bytes, passphrase: str):
    """Encrypt plaintext using AES-GCM. Returns (ciphertext, nonce, tag, salt)."""
    salt = get_random_bytes(16)
    key = _derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, cipher.nonce, tag, salt

def decrypt_message(ciphertext: bytes, passphrase: str, nonce: bytes, tag: bytes, salt: bytes) -> bytes:
    key = _derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# --- Hashing ---

def sha256_hex(data: bytes) -> str:
    h = SHA256.new(data)
    return h.hexdigest()

# --- Digital Signatures (Ed25519) ---

def generate_signing_keypair():
    """Return (private_key_obj, public_key_obj)."""
    priv = ECC.generate(curve='Ed25519')
    pub = priv.public_key()
    return priv, pub

def sign_bytes(data: bytes, private_key) -> bytes:
    signer = eddsa.new(private_key, 'rfc8032')
    return signer.sign(data)

def verify_signature(data: bytes, signature: bytes, public_key_der: bytes) -> bool:
    try:
        pub = ECC.import_key(public_key_der)
        verifier = eddsa.new(pub, 'rfc8032')
        verifier.verify(data, signature)
        return True
    except Exception:
        return False
