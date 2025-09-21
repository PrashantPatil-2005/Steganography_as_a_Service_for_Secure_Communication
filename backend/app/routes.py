# All API routes are in this one file
from flask import request, jsonify, Blueprint, current_app, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os
import mimetypes
import io
from .models import User, Message
from . import db
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

# Auth endpoints
@api.route('/register', methods=['POST'])
def register_user():
    data = request.get_json() or {}
    if not all(k in data for k in ('username', 'email', 'password')):
        return jsonify({'message': 'Missing username, email, or password'}), 400

    if User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Username or email already exists'}), 409

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created successfully!'}), 201

@api.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    if not all(k in data for k in ('username', 'password')):
        return jsonify({'message': 'Missing username or password'}), 400
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = create_access_token(identity=str(user.id), expires_delta=timedelta(hours=8))
    return jsonify({'access_token': token}), 200

# Stego endpoints
@api.route('/stego/embed', methods=['POST'])
@jwt_required(optional=True)
def stego_embed():
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

    # Encrypt the message
    ciphertext, nonce, tag, salt = encrypt_message(message.encode('utf-8'), passphrase)
    payload = b'|'.join([salt, nonce, tag, ciphertext])

    # Embed into image (baseline LSB)
    stego_output = os.path.join(current_app.config['STEGO_TEMP_FOLDER'], f"stego_{filename}")
    try:
        embed_message_in_image(upload_path, payload, stego_output)
    except Exception as e:
        try:
            os.remove(upload_path)
        except Exception:
            pass
        return jsonify({'message': f'Embedding failed: {str(e)}'}), 500

    # Hash and optional sign
    with open(stego_output, 'rb') as f:
        stego_bytes = f.read()
    stego_hash_hex = sha256_hex(stego_bytes)
    signature = None
    public_key = None
    if want_sign:
        privkey, pubkey = generate_signing_keypair()
        signature = sign_bytes(bytes.fromhex(stego_hash_hex), privkey)
        public_key = pubkey.export_key(format='DER')

    # Determine expiry
    expires_at = None
    if expires_in:
        try:
            expires_at = datetime.utcnow() + timedelta(seconds=int(expires_in))
        except ValueError:
            pass

    # Store metadata
    user_id = get_jwt_identity()
    msg = Message(
        user_id=int(user_id) if user_id else None,
        filename=os.path.basename(stego_output),
        mime_type=mimetypes.guess_type(stego_output)[0] or 'application/octet-stream',
        stego_hash=stego_hash_hex,
        signature=signature,
        public_key=public_key,
        is_canary=is_canary,
        expires_at=expires_at,
    )
    db.session.add(msg)
    db.session.commit()

    # Clean original upload
    try:
        os.remove(upload_path)
    except Exception:
        pass

    # Return file and metadata
    return jsonify({
        'message': 'Embedded successfully',
        'message_id': msg.id,
        'stego_hash': stego_hash_hex,
        'public_key_der_hex': (public_key.hex() if public_key else None),
        'stego_filename': os.path.basename(stego_output),
        'download_path': f"/api/stego/download/{msg.id}"
    }), 201

@api.route('/stego/download/<int:message_id>', methods=['GET'])
def stego_download(message_id):
    msg = Message.query.get_or_404(message_id)
    path = os.path.join(current_app.config['STEGO_TEMP_FOLDER'], msg.filename)
    if not os.path.exists(path):
        return jsonify({'message': 'File not found'}), 404
    return send_file(path, as_attachment=True, download_name=msg.filename)

@api.route('/stego/extract', methods=['POST'])
def stego_extract():
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

    try:
        payload = extract_message_from_image(temp_path)
    except Exception as e:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        return jsonify({'message': f'Extraction failed: {str(e)}'}), 500

    # Canary logic with optional message_id
    if message_id:
        msg = Message.query.get(message_id)
        if msg:
            # Verify hash of provided file
            with open(temp_path, 'rb') as f:
                b = f.read()
            this_hash = sha256_hex(b)
            if msg.expires_at and datetime.utcnow() > msg.expires_at:
                # Serve canary content
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
                return jsonify({'message': 'Access expired', 'canary': True, 'data': 'This is a decoy.'}), 403
            if this_hash != msg.stego_hash:
                # Tampered file -> canary
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
                return jsonify({'message': 'Tamper detected', 'canary': True, 'data': 'This is a decoy.'}), 400
            # Optional signature verify
            if msg.public_key and msg.signature:
                try:
                    ok = verify_signature(bytes.fromhex(this_hash), msg.signature, msg.public_key)
                    if not ok:
                        return jsonify({'message': 'Signature verification failed'}), 400
                except Exception:
                    return jsonify({'message': 'Signature verification error'}), 400

    try:
        salt, nonce, tag, ciphertext = payload.split(b'|', 3)
        plaintext = decrypt_message(ciphertext, passphrase, nonce, tag, salt)
    except Exception as e:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        return jsonify({'message': f'Decryption failed: {str(e)}'}), 400

    try:
        os.remove(temp_path)
    except Exception:
        pass

    return jsonify({'message': 'Extracted successfully', 'data': plaintext.decode('utf-8')}), 200

@api.route('/stego/analysis', methods=['POST'])
def analyze_stego():
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    filename = secure_filename(file.filename)
    temp_path = os.path.join(current_app.config['STEGO_TEMP_FOLDER'], f"_analysis_{filename}")
    file.save(temp_path)
    try:
        score = chi_square_lsb(temp_path)
    finally:
        try:
            os.remove(temp_path)
        except Exception:
            pass
    return jsonify({'chi_square_score': score}), 200