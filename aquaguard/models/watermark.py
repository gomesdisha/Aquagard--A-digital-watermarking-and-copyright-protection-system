from ..utils.db import db
import datetime
import json

class Watermark(db.Model):
    __tablename__ = 'watermarks'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    original_file_path = db.Column(db.String(255), nullable=False)
    watermarked_file_path = db.Column(db.String(255), nullable=False)
    watermark_data = db.Column(db.Text, nullable=False)  # JSON string containing watermark info
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-3 hash of original file
    encryption_key = db.Column(db.String(64), nullable=False)  # AES-256 key (encrypted)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    file_type = db.Column(db.String(20), nullable=False)  # Image, PDF, etc.
    
    def set_watermark_data(self, data_dict):
        """Store watermark data as JSON string"""
        self.watermark_data = json.dumps(data_dict)
    
    def get_watermark_data(self):
        """Retrieve watermark data as dictionary"""
        return json.loads(self.watermark_data)
    
    def __repr__(self):
        return f'<Watermark {self.id} for file {self.file_name}>'