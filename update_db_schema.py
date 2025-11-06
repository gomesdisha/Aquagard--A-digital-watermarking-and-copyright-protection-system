import sqlite3
import os

def update_database_schema():
    """Update the database schema to match the Watermark model"""
    db_path = os.path.join('instance', 'aquaguard.db')
    
    if not os.path.exists(db_path):
        print(f"Database file not found at {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if columns exist
    cursor.execute("PRAGMA table_info(watermarks)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Add missing columns
    if 'original_file_path' not in columns:
        cursor.execute('ALTER TABLE watermarks ADD COLUMN original_file_path TEXT DEFAULT ""')
        print("Added column: original_file_path")
    
    if 'watermarked_file_path' not in columns:
        cursor.execute('ALTER TABLE watermarks ADD COLUMN watermarked_file_path TEXT DEFAULT ""')
        print("Added column: watermarked_file_path")
    
    if 'watermark_data' not in columns:
        cursor.execute('ALTER TABLE watermarks ADD COLUMN watermark_data TEXT DEFAULT "{}"')
        print("Added column: watermark_data")
    
    if 'file_type' not in columns:
        cursor.execute('ALTER TABLE watermarks ADD COLUMN file_type TEXT DEFAULT "unknown"')
        print("Added column: file_type")
        # Create index for file_type if it doesn't exist
        try:
            cursor.execute('CREATE INDEX ix_watermarks_file_type ON watermarks (file_type)')
            print("Created index for file_type")
        except sqlite3.OperationalError:
            print("Index for file_type already exists")
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print("Database schema updated successfully!")

if __name__ == "__main__":
    update_database_schema()