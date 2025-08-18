# All API routes are in this one file
from flask import request, jsonify, Blueprint
from werkzeug.security import generate_password_hash
from .models import User
from . import db

# This line creates the 'api' object that __init__.py is looking for
api = Blueprint('api', __name__)

# This is the user registration endpoint we planned
@api.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

    if not data or not 'username' in data or not 'password' in data or not 'email' in data:
        return jsonify({'message': 'Missing username, email, or password'}), 400

    if User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Username or email already exists'}), 409

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha26')

    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created successfully!'}), 201