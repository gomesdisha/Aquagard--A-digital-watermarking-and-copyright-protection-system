import sqlite3
import os
from werkzeug.security import generate_password_hash

def fix_database():
    """Fix the database by recreating it from scratch"""
    db_path = os.path.join('instance', 'aquaguard.db')
    
    # Delete the database if it exists
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Deleted existing database at {db_path}")
    
    # Create a new database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        registration_number TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create watermarks table
    cursor.execute('''
    CREATE TABLE watermarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        encryption_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX ix_watermarks_user_id ON watermarks (user_id)')
    cursor.execute('CREATE INDEX ix_watermarks_file_hash ON watermarks (file_hash)')
    
    # Create admin user
    cursor.execute('''
    INSERT INTO users (name, email, registration_number, password_hash)
    VALUES (?, ?, ?, ?)
    ''', ('Admin User', 'admin@aquaguard.com', 'ADMIN001', generate_password_hash('admin123')))
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print("Database fixed successfully!")

if __name__ == "__main__":
    fix_database()