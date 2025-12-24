"""
Vercel serverless function - Ultra-lightweight Flask API for Steganography
100% pure Python libraries (no C extensions) to stay well under 250MB

Dependencies:
- Flask + flask-cors (~2MB)
- pypng (~50KB) - pure Python PNG
- pyaes (~10KB) - pure Python AES
Total: ~5MB installed (vs 250MB limit)
"""
import os
import uuid
import hmac
import hashlib
import secrets
import struct
from io import BytesIO
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Pure Python libraries (no C extensions)
import png
import pyaes

# ==================== CONFIG ====================
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    UPLOAD_FOLDER = '/tmp/uploads'
    STEGO_TEMP_FOLDER = '/tmp/stego_tmp'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'png'}

# ==================== SECURITY (Pure Python AES-CTR + HMAC) ====================
def _derive_key(passphrase: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation (pure Python)."""
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, iterations, dklen=64)

def encrypt_message(plaintext: bytes, passphrase: str):
    """
    Encrypt using AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC).
    Returns (ciphertext, iv, mac, salt).
    """
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    
    # Derive 64 bytes: 32 for encryption, 32 for MAC
    key_material = _derive_key(passphrase, salt)
    enc_key = key_material[:32]
    mac_key = key_material[32:]
    
    # AES-256-CTR encryption
    aes = pyaes.AESModeOfOperationCTR(enc_key, pyaes.Counter(int.from_bytes(iv, 'big')))
    ciphertext = aes.encrypt(plaintext)
    
    # HMAC-SHA256 over IV + ciphertext
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    
    return ciphertext, iv, mac, salt

def decrypt_message(ciphertext: bytes, passphrase: str, iv: bytes, mac: bytes, salt: bytes) -> bytes:
    """Decrypt and verify AES-256-CTR + HMAC-SHA256."""
    key_material = _derive_key(passphrase, salt)
    enc_key = key_material[:32]
    mac_key = key_material[32:]
    
    # Verify MAC first (constant-time comparison)
    expected_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError('Authentication failed - message tampered or wrong passphrase')
    
    # Decrypt
    aes = pyaes.AESModeOfOperationCTR(enc_key, pyaes.Counter(int.from_bytes(iv, 'big')))
    return aes.decrypt(ciphertext)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ==================== STEGANOGRAPHY (Pure Python with pypng) ====================
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
    """Embed payload into PNG using LSB steganography."""
    reader = png.Reader(filename=input_path)
    w, h, rows, metadata = reader.read()
    
    pixels = [list(row) for row in rows]
    planes = metadata.get('planes', 3)
    has_alpha = metadata.get('alpha', False)
    
    total_values = w * h * 3
    required_bits = (4 + len(payload)) * 8
    if required_bits > total_values:
        raise ValueError('Cover image too small for payload')
    
    length_prefix = len(payload).to_bytes(4, 'big')
    bit_stream = list(_bytes_to_bits(length_prefix + payload))
    bit_idx = 0
    
    for row in pixels:
        for i in range(0, len(row), planes):
            for c in range(min(3, planes)):
                if bit_idx < len(bit_stream):
                    row[i + c] = (row[i + c] & 0xFE) | bit_stream[bit_idx]
                    bit_idx += 1
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    writer = png.Writer(width=w, height=h, greyscale=False, alpha=has_alpha, bitdepth=metadata.get('bitdepth', 8))
    with open(output_path, 'wb') as f:
        writer.write(f, pixels)

def extract_message_from_image(input_path: str) -> bytes:
    """Extract hidden payload from PNG using LSB."""
    reader = png.Reader(filename=input_path)
    w, h, rows, metadata = reader.read()
    planes = metadata.get('planes', 3)
    
    bits = []
    for row in rows:
        row_list = list(row)
        for i in range(0, len(row_list), planes):
            for c in range(min(3, planes)):
                bits.append(row_list[i + c] & 1)
    
    length_bytes = _bits_to_bytes(bits[:32])
    length = int.from_bytes(length_bytes, 'big')
    
    if 32 + length * 8 > len(bits):
        raise ValueError('Not enough data for payload length')
    
    return _bits_to_bytes(bits[32:32 + length * 8])

def chi_square_lsb(image_path: str) -> float:
    """Chi-square analysis for LSB detection."""
    reader = png.Reader(filename=image_path)
    w, h, rows, metadata = reader.read()
    planes = metadata.get('planes', 3)
    
    zeros = ones = 0
    for row in rows:
        row_list = list(row)
        for i in range(0, len(row_list), planes):
            for c in range(min(3, planes)):
                if row_list[i + c] & 1:
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
        'note': 'PNG images only supported',
        'endpoints': ['POST /api/stego/embed', 'GET /api/stego/download/<id>', 'POST /api/stego/extract', 'POST /api/stego/analysis', 'GET /api/health']
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
        return jsonify({'message': 'Only PNG files supported'}), 400
    if not message:
        return jsonify({'message': 'Missing message'}), 400
    if not passphrase:
        return jsonify({'message': 'Missing passphrase'}), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.png'):
        filename += '.png'
    
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(upload_path)

    # Encrypt: ciphertext, iv, mac, salt
    ciphertext, iv, mac, salt = encrypt_message(message.encode('utf-8'), passphrase)
    
    # Pack: 4 lengths (salt, iv, mac, ciphertext) + data
    def u32(n): return int(n).to_bytes(4, 'big')
    payload = b''.join([u32(len(salt)), u32(len(iv)), u32(len(mac)), u32(len(ciphertext)), salt, iv, mac, ciphertext])

    message_id = str(uuid.uuid4())
    stego_output = os.path.join(app.config['STEGO_TEMP_FOLDER'], f"stego_{message_id}_{filename}")
    
    try:
        embed_message_in_image(upload_path, payload, stego_output)
    except Exception as e:
        try: os.remove(upload_path)
        except: pass
        return jsonify({'message': f'Embedding failed: {str(e)}'}), 500

    with open(stego_output, 'rb') as f:
        stego_hash = sha256_hex(f.read())

    try: os.remove(upload_path)
    except: pass

    return jsonify({
        'message': 'Embedded successfully',
        'message_id': message_id,
        'stego_hash': stego_hash,
        'stego_filename': os.path.basename(stego_output),
        'download_path': f"/api/stego/download/{message_id}"
    }), 201

@app.route('/api/stego/download/<message_id>', methods=['GET'])
def stego_download(message_id):
    folder = app.config['STEGO_TEMP_FOLDER']
    try:
        for fn in os.listdir(folder):
            if fn.startswith('stego_') and message_id in fn:
                return send_file(os.path.join(folder, fn), as_attachment=True, download_name=fn)
    except: pass
    return jsonify({'message': 'File not found'}), 404

@app.route('/api/stego/preview/<message_id>', methods=['GET'])
def stego_preview(message_id):
    folder = app.config['STEGO_TEMP_FOLDER']
    try:
        for fn in os.listdir(folder):
            if fn.startswith('stego_') and message_id in fn:
                return send_file(os.path.join(folder, fn), as_attachment=False, download_name=fn)
    except: pass
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
        
        if len(payload) < 16:
            raise ValueError('Payload malformed')
        
        off = 0
        def r32(d, i): return int.from_bytes(d[i:i+4], 'big')
        ls, li, lm, lc = r32(payload, 0), r32(payload, 4), r32(payload, 8), r32(payload, 12)
        off = 16
        
        if len(payload) - off < ls + li + lm + lc:
            raise ValueError('Payload malformed')
        
        salt = payload[off:off+ls]; off += ls
        iv = payload[off:off+li]; off += li
        mac = payload[off:off+lm]; off += lm
        ciphertext = payload[off:off+lc]
        
        plaintext = decrypt_message(ciphertext, passphrase, iv, mac, salt)
        
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
