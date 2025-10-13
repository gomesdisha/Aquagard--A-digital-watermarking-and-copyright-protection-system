from ..utils.db import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import datetime

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    registration_number = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    watermarks = db.relationship('Watermark', backref='owner', lazy=True)
    
    def set_password(self, password):
        # Using SHA-3 (SHA3-256) for password hashing as specified in requirements
        sha3_hash = hashlib.sha3_256(password.encode()).hexdigest()
        # Additional layer of security with werkzeug
        self.password_hash = generate_password_hash(sha3_hash)
    
    def check_password(self, password):
        # Convert password to SHA-3 hash first
        sha3_hash = hashlib.sha3_256(password.encode()).hexdigest()
        # Then check against stored hash
        return check_password_hash(self.password_hash, sha3_hash)
    
    def __repr__(self):
        return f'<User {self.email}>'