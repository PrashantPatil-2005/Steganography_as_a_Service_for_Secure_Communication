# All API routes are in this one file
from flask import request, jsonify, Blueprint, current_app, send_file
from werkzeug.utils import secure_filename
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os
import mimetypes
import io
import uuid
from .steganography import embed_message_in_image, extract_message_from_image
from .security import (
    encrypt_message,
    decrypt_message,
    sha256_hex,
    generate_signing_keypair,
    sign_bytes,
    verify_signature,
)
from .steganalysis import chi_square_lsb

# This line creates the 'api' object that __init__.py is looking for
api = Blueprint('api', __name__)

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in current_app.config['ALLOWED_EXTENSIONS']

# Basic index and health endpoints for quick checks
@api.route('/', methods=['GET'])
def api_index():
    current_app.logger.debug('GET /api invoked for index')
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

@api.route('/health', methods=['GET'])
def api_health():
    current_app.logger.debug('GET /api/health invoked')
    return jsonify({'status': 'ok'}), 200

# Stego endpoints (no database required)
@api.route('/stego/embed', methods=['POST'])
@jwt_required(optional=True)
def stego_embed():
    current_app.logger.debug('POST /api/stego/embed invoked')
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    file = request.files['file']
    message = request.form.get('message')
    passphrase = request.form.get('passphrase')
    want_sign = request.form.get('sign', 'false').lower() == 'true'
    is_canary = request.form.get('canary', 'false').lower() == 'true'
    expires_in = request.form.get('expires_in_seconds')

    if not file or file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if not allowed_file(file.filename):
        return jsonify({'message': 'File type not allowed'}), 400
    if not message:
        return jsonify({'message': 'Missing message'}), 400
    if not passphrase:
        return jsonify({'message': 'Missing passphrase'}), 400

    filename = secure_filename(file.filename)
    upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    file.save(upload_path)
    current_app.logger.debug(f'Uploaded file saved to {upload_path}')

    # Encrypt the message
    ciphertext, nonce, tag, salt = encrypt_message(message.encode('utf-8'), passphrase)
    payload = b'|'.join([salt, nonce, tag, ciphertext])

    # Embed into image (baseline LSB)
    # Generate unique message ID early to include in output filename
    message_id = str(uuid.uuid4())
    stego_output = os.path.join(
        current_app.config['STEGO_TEMP_FOLDER'], f"stego_{message_id}_{filename}"
    )
    try:
        current_app.logger.debug('Embedding payload into image')
        embed_message_in_image(upload_path, payload, stego_output)
    except Exception as e:
        current_app.logger.exception('Embedding failed')
        try:
            os.remove(upload_path)
        except Exception:
            pass
        return jsonify({'message': f'Embedding failed: {str(e)}'}), 500

    # Hash and optional sign
    with open(stego_output, 'rb') as f:
        stego_bytes = f.read()
    stego_hash_hex = sha256_hex(stego_bytes)
    current_app.logger.debug(f'Stego file written to {stego_output}, sha256={stego_hash_hex}')
    signature = None
    public_key = None
    if want_sign:
        privkey, pubkey = generate_signing_keypair()
        signature = sign_bytes(bytes.fromhex(stego_hash_hex), privkey)
        public_key = pubkey.export_key(format='DER')

    # Clean original upload
    try:
        os.remove(upload_path)
    except Exception:
        pass

    # Return file and metadata
    return jsonify({
        'message': 'Embedded successfully',
        'message_id': message_id,
        'stego_hash': stego_hash_hex,
        'public_key_der_hex': (public_key.hex() if public_key else None),
        'stego_filename': os.path.basename(stego_output),
        'download_path': f"/api/stego/download/{message_id}"
    }), 201

@api.route('/stego/download/<message_id>', methods=['GET'])
def stego_download(message_id):
    current_app.logger.debug(f'GET /api/stego/download/{message_id} invoked')
    # Find the stego file by message_id in the temp folder
    stego_folder = current_app.config['STEGO_TEMP_FOLDER']
    for filename in os.listdir(stego_folder):
        if filename.startswith('stego_'):
            # Extract message_id from filename or use a simple mapping
            # For this simple implementation, we'll assume message_id matches the filename pattern
            if message_id in filename:
                path = os.path.join(stego_folder, filename)
                if os.path.exists(path):
                    current_app.logger.debug(f'Returning stego file for download {path}')
                    return send_file(path, as_attachment=True, download_name=filename)
    current_app.logger.warning(f'Stego file not found for message_id={message_id}')
    return jsonify({'message': 'File not found'}), 404

@api.route('/stego/preview/<message_id>', methods=['GET'])
def stego_preview(message_id):
    current_app.logger.debug(f'GET /api/stego/preview/{message_id} invoked')
    stego_folder = current_app.config['STEGO_TEMP_FOLDER']
    for filename in os.listdir(stego_folder):
        if filename.startswith('stego_') and message_id in filename:
            path = os.path.join(stego_folder, filename)
            if os.path.exists(path):
                current_app.logger.debug(f'Returning stego file inline {path}')
                return send_file(path, as_attachment=False, download_name=filename)
    current_app.logger.warning(f'Stego preview not found for message_id={message_id}')
    return jsonify({'message': 'File not found'}), 404

@api.route('/stego/extract', methods=['POST'])
def stego_extract():
    current_app.logger.debug('POST /api/stego/extract invoked')
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    file = request.files['file']
    passphrase = request.form.get('passphrase')
    message_id = request.form.get('message_id')

    if not file or file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if not passphrase:
        return jsonify({'message': 'Missing passphrase'}), 400

    filename = secure_filename(file.filename)
    temp_path = os.path.join(current_app.config['STEGO_TEMP_FOLDER'], f"_extract_{filename}")
    file.save(temp_path)
    current_app.logger.debug(f'Temporary extract file saved to {temp_path}')

    try:
        payload = extract_message_from_image(temp_path)
    except Exception as e:
        current_app.logger.exception('Extraction from image failed')
        try:
            os.remove(temp_path)
        except Exception:
            pass
        return jsonify({'message': f'Extraction failed: {str(e)}'}), 500

    # Simple canary logic (without database)
    if message_id:
        # For this simplified version, we'll skip database-based canary logic
        # In a real implementation, you might use a simple in-memory store or file-based storage
        pass

    try:
        salt, nonce, tag, ciphertext = payload.split(b'|', 3)
        plaintext = decrypt_message(ciphertext, passphrase, nonce, tag, salt)
    except Exception as e:
        current_app.logger.exception('Decryption failed')
        try:
            os.remove(temp_path)
        except Exception:
            pass
        return jsonify({'message': f'Decryption failed: {str(e)}'}), 400

    try:
        os.remove(temp_path)
    except Exception:
        pass

    current_app.logger.debug('Extraction and decryption successful')
    return jsonify({'message': 'Extracted successfully', 'data': plaintext.decode('utf-8')}), 200

@api.route('/stego/analysis', methods=['POST'])
def analyze_stego():
    current_app.logger.debug('POST /api/stego/analysis invoked')
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    filename = secure_filename(file.filename)
    temp_path = os.path.join(current_app.config['STEGO_TEMP_FOLDER'], f"_analysis_{filename}")
    file.save(temp_path)
    current_app.logger.debug(f'Temporary analysis file saved to {temp_path}')
    try:
        score = chi_square_lsb(temp_path)
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass
    current_app.logger.debug(f'Chi-square score computed: {score}')
    return jsonify({'chi_square_score': score}), 200