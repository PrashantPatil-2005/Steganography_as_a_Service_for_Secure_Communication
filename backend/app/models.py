# Database models (User, etc.)
from . import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(64), nullable=True)
    stego_hash = db.Column(db.String(64), nullable=False)  # hex SHA-256
    signature = db.Column(db.LargeBinary, nullable=True)
    public_key = db.Column(db.LargeBinary, nullable=True)
    is_canary = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __repr__(self):
        return f'<Message {self.id} file={self.filename}>'