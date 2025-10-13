#!/usr/bin/env python
from aquaguard import create_app
from aquaguard.utils.db import db
from aquaguard.models.user import User

def setup_database():
    app = create_app()
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(email='admin@aquaguard.com').first()
        if not admin:
            # Create admin user if it doesn't exist
            admin = User(
                name='Admin',
                email='admin@aquaguard.com',
                registration_number='ADMIN001',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        
        print("Database setup completed successfully!")

if __name__ == '__main__':
    setup_database()