#!/usr/bin/env python
from aquaguard import create_app
from aquaguard.utils.db import db
from aquaguard.models.user import User
from werkzeug.security import generate_password_hash

def create_admin_user():
    app = create_app()
    with app.app_context():
        # Delete existing admin if any
        admin = User.query.filter_by(email='admin@aquaguard.com').first()
        if admin:
            db.session.delete(admin)
            db.session.commit()
            print("Deleted existing admin user")
        
        # Create new admin with direct password hash
        new_admin = User(
            name='Admin',
            email='admin@aquaguard.com',
            registration_number='ADMIN001',
            password_hash=generate_password_hash('admin123')
        )
        db.session.add(new_admin)
        db.session.commit()
        print("Created new admin user with email: admin@aquaguard.com and password: admin123")

if __name__ == '__main__':
    create_admin_user()