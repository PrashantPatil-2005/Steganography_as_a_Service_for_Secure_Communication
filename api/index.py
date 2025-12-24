"""
Vercel serverless function - Ultra-lightweight Flask API for Steganography
Uses pure Python libraries only (no C extensions) to stay under 250MB
"""
import os
import uuid
import hmac
import hashlib
import secrets
import struct
import zlib
from io import BytesIO
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Pure Python PNG library (no C extensions, tiny size)
import png

# Use cryptography for AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ==================== CONFIG ====================
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    UPLOAD_FOLDER = '/tmp/uploads'
    STEGO_TEMP_FOLDER = '/tmp/stego_tmp'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'png'}  # Only PNG for pure Python implementation

# ==================== SECURITY ====================
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
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, nonce, salt

def decrypt_message(ciphertext: bytes, passphrase: str, nonce: bytes, salt: bytes) -> bytes:
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

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
    """Embed payload into PNG using LSB steganography with pypng."""
    # Read PNG
    reader = png.Reader(filename=input_path)
    w, h, rows, metadata = reader.read()
    
    # Convert to list of pixel rows
    pixels = []
    planes = metadata.get('planes', 3)
    has_alpha = metadata.get('alpha', False)
    
    for row in rows:
        row_list = list(row)
        pixels.append(row_list)
    
    # Calculate capacity
    total_values = w * h * 3  # RGB channels only
    required_bits = (4 + len(payload)) * 8
    if required_bits > total_values:
        raise ValueError('Cover image too small for payload')
    
    # Create bit stream with length prefix
    length_prefix = len(payload).to_bytes(4, 'big')
    bit_stream = list(_bytes_to_bits(length_prefix + payload))
    bit_idx = 0
    
    # Embed into LSB of RGB values
    for row in pixels:
        for i in range(0, len(row), planes):
            for c in range(min(3, planes)):  # Only R, G, B
                if bit_idx < len(bit_stream):
                    row[i + c] = (row[i + c] & 0xFE) | bit_stream[bit_idx]
                    bit_idx += 1
    
    # Write output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    writer = png.Writer(
        width=w,
        height=h,
        greyscale=False,
        alpha=has_alpha,
        bitdepth=metadata.get('bitdepth', 8)
    )
    
    with open(output_path, 'wb') as f:
        writer.write(f, pixels)

def extract_message_from_image(input_path: str) -> bytes:
    """Extract hidden payload from PNG using LSB."""
    reader = png.Reader(filename=input_path)
    w, h, rows, metadata = reader.read()
    
    planes = metadata.get('planes', 3)
    
    # Extract LSBs
    bits = []
    for row in rows:
        row_list = list(row)
        for i in range(0, len(row_list), planes):
            for c in range(min(3, planes)):
                bits.append(row_list[i + c] & 1)
    
    # First 32 bits = length
    length_bytes = _bits_to_bytes(bits[:32])
    length = int.from_bytes(length_bytes, 'big')
    total_bits_needed = 32 + length * 8
    
    if total_bits_needed > len(bits):
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
        'note': 'Only PNG images supported',
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
        return jsonify({'message': 'Only PNG files are supported'}), 400
    if not message:
        return jsonify({'message': 'Missing message'}), 400
    if not passphrase:
        return jsonify({'message': 'Missing passphrase'}), 400

    filename = secure_filename(file.filename)
    # Ensure .png extension
    if not filename.lower().endswith('.png'):
        filename += '.png'
    
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(upload_path)

    # Encrypt
    ciphertext, nonce, salt = encrypt_message(message.encode('utf-8'), passphrase)
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
