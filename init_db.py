from aquaguard import create_app
from aquaguard.utils.db import db
from werkzeug.security import generate_password_hash
from aquaguard.models.user import User
import os

def init_database():
    """Initialize the database and create admin user if it doesn't exist"""
    app = create_app()
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(email='admin@aquaguard.com').first()
        if not admin:
            # Create admin user
            admin_user = User(
                name='Admin User',
                email='admin@aquaguard.com',
                registration_number='ADMIN001',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully!")
        
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_database()