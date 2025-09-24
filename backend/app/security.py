# Encryption, signatures, canaries

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
import logging

# --- Symmetric Encryption (AES-GCM) ---

def _derive_key(passphrase: str, salt: bytes, iterations: int = 200_000) -> bytes:
    logging.debug(f'Deriving key with PBKDF2: iterations={iterations}, salt_len={len(salt)}')
    return PBKDF2(passphrase, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

def encrypt_message(plaintext: bytes, passphrase: str):
    """Encrypt plaintext using AES-GCM. Returns (ciphertext, nonce, tag, salt)."""
    salt = get_random_bytes(16)
    key = _derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    logging.debug(f'Encrypted message: plaintext_len={len(plaintext)}, ciphertext_len={len(ciphertext)}')
    return ciphertext, cipher.nonce, tag, salt

def decrypt_message(ciphertext: bytes, passphrase: str, nonce: bytes, tag: bytes, salt: bytes) -> bytes:
    key = _derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    logging.debug(f'Decrypted message: ciphertext_len={len(ciphertext)}, plaintext_len={len(plaintext)}')
    return plaintext

# --- Hashing ---

def sha256_hex(data: bytes) -> str:
    h = SHA256.new(data)
    digest = h.hexdigest()
    logging.debug(f'sha256_hex computed: length={len(data)}, digest={digest}')
    return digest

# --- Digital Signatures (Ed25519) ---

def generate_signing_keypair():
    """Return (private_key_obj, public_key_obj)."""
    priv = ECC.generate(curve='Ed25519')
    pub = priv.public_key()
    logging.debug('Generated new Ed25519 keypair')
    return priv, pub

def sign_bytes(data: bytes, private_key) -> bytes:
    signer = eddsa.new(private_key, 'rfc8032')
    signature = signer.sign(data)
    logging.debug(f'Signed data: data_len={len(data)}, sig_len={len(signature)}')
    return signature

def verify_signature(data: bytes, signature: bytes, public_key_der: bytes) -> bool:
    try:
        pub = ECC.import_key(public_key_der)
        verifier = eddsa.new(pub, 'rfc8032')
        verifier.verify(data, signature)
        logging.debug('Signature verification succeeded')
        return True
    except Exception:
        logging.debug('Signature verification failed')
        return False
