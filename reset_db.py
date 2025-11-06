from aquaguard import create_app
from aquaguard.utils.db import db
from werkzeug.security import generate_password_hash
from aquaguard.models.user import User
import os

def reset_database():
    """Reset the database by dropping all tables and recreating them"""
    app = create_app()
    
    with app.app_context():
        # Drop all tables
        db.drop_all()
        print("All tables dropped successfully!")
        
        # Create all tables
        db.create_all()
        print("All tables recreated successfully!")
        
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
        
        print("Database reset completed successfully!")

if __name__ == "__main__":
    reset_database()