"""
Vercel serverless function - Lightweight Flask API for Steganography
Uses pure Python crypto and Pillow-SIMD/minimal deps to stay under 250MB
"""
import os
import sys
import uuid
import hmac
import hashlib
import secrets
import struct
from io import BytesIO
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Use cryptography (smaller) instead of pycryptodome
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Pillow for image processing (required for steganography)
from PIL import Image

# ==================== CONFIG ====================
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    UPLOAD_FOLDER = '/tmp/uploads'
    STEGO_TEMP_FOLDER = '/tmp/stego_tmp'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}

# ==================== SECURITY (using cryptography library) ====================
def _derive_key(passphrase: str, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_message(plaintext: bytes, passphrase: str):
    """Encrypt using AES-GCM. Returns (ciphertext_with_tag, nonce, salt)."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # includes auth tag
    return ciphertext, nonce, salt

def decrypt_message(ciphertext: bytes, passphrase: str, nonce: bytes, salt: bytes) -> bytes:
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ==================== STEGANOGRAPHY (pure Python) ====================
def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def _bits_to_bytes(bits):
    out = bytearray()
    cur = 0
    count = 0
    for b in bits:
        cur = (cur << 1) | (b & 1)
        count += 1
        if count == 8:
            out.append(cur)
            cur = 0
            count = 0
    if count != 0:
        cur = cur << (8 - count)
        out.append(cur)
    return bytes(out)

def embed_message_in_image(input_path: str, payload: bytes, output_path: str):
    with Image.open(input_path) as img:
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        has_alpha = img.mode == 'RGBA'
        pixels = list(img.getdata())
        width, height = img.size

    total_channels = len(pixels) * 3
    required_bits = (4 + len(payload)) * 8
    if required_bits > total_channels:
        raise ValueError('Cover image too small for payload')

    length_prefix = len(payload).to_bytes(4, 'big')
    bit_stream = list(_bytes_to_bits(length_prefix + payload))
    bit_iter = iter(bit_stream)

    new_pixels = []
    for p in pixels:
        r, g, b = p[:3]
        try:
            r = (r & 0xFE) | next(bit_iter)
        except StopIteration:
            new_pixels.append(p)
            continue
        try:
            g = (g & 0xFE) | next(bit_iter)
        except StopIteration:
            new_pixels.append((r, g, b, p[3]) if has_alpha else (r, g, b))
            continue
        try:
            b = (b & 0xFE) | next(bit_iter)
        except StopIteration:
            new_pixels.append((r, g, b, p[3]) if has_alpha else (r, g, b))
            continue
        new_pixels.append((r, g, b, p[3]) if has_alpha else (r, g, b))

    mode = 'RGBA' if has_alpha else 'RGB'
    out_img = Image.new(mode, (width, height))
    out_img.putdata(new_pixels)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    out_img.save(output_path, format='PNG')

def extract_message_from_image(input_path: str) -> bytes:
    with Image.open(input_path) as img:
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        pixels = list(img.getdata())

    bits = []
    for p in pixels:
        r, g, b = p[:3]
        bits.extend([r & 1, g & 1, b & 1])

    length_bytes = _bits_to_bytes(bits[:32])
    length = int.from_bytes(length_bytes, 'big')
    total_bits_needed = 32 + length * 8
    if total_bits_needed > len(bits):
        raise ValueError('Not enough data for payload length')
    return _bits_to_bytes(bits[32:32 + length * 8])

def chi_square_lsb(image_path: str) -> float:
    with Image.open(image_path) as img:
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        pixels = list(img.getdata())

    zeros = ones = 0
    for p in pixels:
        for c in p[:3]:
            if c & 1:
                ones += 1
            else:
                zeros += 1

    total = zeros + ones
    if total == 0:
        return 0.0
    expected = total / 2.0
    return ((zeros - expected) ** 2) / expected + ((ones - expected) ** 2) / expected

# ==================== FLASK APP ====================
app = Flask(__name__)
app.config.from_object(Config)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Ensure folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['STEGO_TEMP_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/api/', methods=['GET'])
@app.route('/api', methods=['GET'])
def api_index():
    return jsonify({
        'name': 'Steganography-as-a-Service API',
        'version': 1,
        'endpoints': [
            'POST /api/stego/embed',
            'GET  /api/stego/download/<message_id>',
            'POST /api/stego/extract',
            'POST /api/stego/analysis',
            'GET  /api/health'
        ]
    }), 200

@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({'status': 'ok'}), 200

@app.route('/api/stego/embed', methods=['POST'])
def stego_embed():
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    
    file = request.files['file']
    message = request.form.get('message')
    passphrase = request.form.get('passphrase')

    if not file or file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if not allowed_file(file.filename):
        return jsonify({'message': 'File type not allowed'}), 400
    if not message:
        return jsonify({'message': 'Missing message'}), 400
    if not passphrase:
        return jsonify({'message': 'Missing passphrase'}), 400

    filename = secure_filename(file.filename)
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(upload_path)

    # Encrypt (simplified format: salt + nonce + ciphertext)
    ciphertext, nonce, salt = encrypt_message(message.encode('utf-8'), passphrase)
    # Format: 3x32-bit lengths + salt + nonce + ciphertext
    def u32(n): return int(n).to_bytes(4, 'big')
    payload = b''.join([u32(len(salt)), u32(len(nonce)), u32(len(ciphertext)), salt, nonce, ciphertext])

    # Embed
    message_id = str(uuid.uuid4())
    stego_output = os.path.join(app.config['STEGO_TEMP_FOLDER'], f"stego_{message_id}_{filename}")
    try:
        embed_message_in_image(upload_path, payload, stego_output)
    except Exception as e:
        try: os.remove(upload_path)
        except: pass
        return jsonify({'message': f'Embedding failed: {str(e)}'}), 500

    # Hash
    with open(stego_output, 'rb') as f:
        stego_bytes = f.read()
    stego_hash_hex = sha256_hex(stego_bytes)

    try: os.remove(upload_path)
    except: pass

    return jsonify({
        'message': 'Embedded successfully',
        'message_id': message_id,
        'stego_hash': stego_hash_hex,
        'stego_filename': os.path.basename(stego_output),
        'download_path': f"/api/stego/download/{message_id}"
    }), 201

@app.route('/api/stego/download/<message_id>', methods=['GET'])
def stego_download(message_id):
    stego_folder = app.config['STEGO_TEMP_FOLDER']
    try:
        for filename in os.listdir(stego_folder):
            if filename.startswith('stego_') and message_id in filename:
                path = os.path.join(stego_folder, filename)
                if os.path.exists(path):
                    return send_file(path, as_attachment=True, download_name=filename)
    except:
        pass
    return jsonify({'message': 'File not found'}), 404

@app.route('/api/stego/preview/<message_id>', methods=['GET'])
def stego_preview(message_id):
    stego_folder = app.config['STEGO_TEMP_FOLDER']
    try:
        for filename in os.listdir(stego_folder):
            if filename.startswith('stego_') and message_id in filename:
                path = os.path.join(stego_folder, filename)
                if os.path.exists(path):
                    return send_file(path, as_attachment=False, download_name=filename)
    except:
        pass
    return jsonify({'message': 'File not found'}), 404

@app.route('/api/stego/extract', methods=['POST'])
def stego_extract():
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    
    file = request.files['file']
    passphrase = request.form.get('passphrase')

    if not file or file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if not passphrase:
        return jsonify({'message': 'Missing passphrase'}), 400

    filename = secure_filename(file.filename)
    temp_path = os.path.join(app.config['STEGO_TEMP_FOLDER'], f"_extract_{filename}")
    file.save(temp_path)

    try:
        payload = extract_message_from_image(temp_path)
    except Exception as e:
        try: os.remove(temp_path)
        except: pass
        return jsonify({'message': f'Extraction failed: {str(e)}'}), 500

    try:
        if len(payload) < 12:
            raise ValueError('Embedded payload malformed')
        off = 0
        def read_u32(data, idx): return int.from_bytes(data[idx:idx+4], 'big')
        ls = read_u32(payload, off); off += 4
        ln = read_u32(payload, off); off += 4
        lc = read_u32(payload, off); off += 4
        if len(payload) - off < ls + ln + lc:
            raise ValueError('Embedded payload malformed')
        salt = payload[off:off+ls]; off += ls
        nonce = payload[off:off+ln]; off += ln
        ciphertext = payload[off:off+lc]
        plaintext = decrypt_message(ciphertext, passphrase, nonce, salt)
    except Exception as e:
        try: os.remove(temp_path)
        except: pass
        return jsonify({'message': f'Decryption failed: {str(e)}'}), 400

    try: os.remove(temp_path)
    except: pass

    return jsonify({'message': 'Extracted successfully', 'data': plaintext.decode('utf-8')}), 200

@app.route('/api/stego/analysis', methods=['POST'])
def stego_analysis():
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    temp_path = os.path.join(app.config['STEGO_TEMP_FOLDER'], f"_analysis_{filename}")
    file.save(temp_path)

    try:
        score = chi_square_lsb(temp_path)
    finally:
        try: os.remove(temp_path)
        except: pass

    return jsonify({'chi_square_score': score}), 200

@app.route('/', methods=['GET'])
def root():
    return jsonify({'message': 'Steganography API', 'api_base': '/api'}), 200
