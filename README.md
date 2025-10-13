# AquaGuard: Digital Watermarking System

AquaGuard is a comprehensive digital watermarking and copyright protection system designed for third-year BTech students. It provides robust file security through invisible watermarks, ensuring content ownership and integrity verification.

## Features

- **LSB Steganography**: Invisible watermarking embedded in image data
- **AES-256 Encryption**: Military-grade encryption of ownership data
- **SHA-3 Hashing**: Cryptographic integrity verification
- **User Authentication**: Secure login and registration system
- **File Management**: Upload, watermark, verify, and download files
- **Responsive UI**: Modern interface built with Bootstrap 5.1.3

## Technology Stack

### Frontend
- HTML5, CSS3, JavaScript
- Bootstrap 5.1.3
- Jinja2 Templates

### Backend
- Python 3.9+
- Flask Web Framework
- SQLAlchemy ORM
- SQLite Database

### Security
- SHA-3 Password Hashing
- AES-256 Encryption
- LSB Steganography
- CSRF Protection

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/aquaguard.git
   cd aquaguard
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Initialize the database:
   ```
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

5. Run the application:
   ```
   flask run
   ```

6. Access the application at http://localhost:5000

## Usage

### User Registration and Login
1. Register with your full name, email, registration number, and password
2. Login with your email and password

### Watermarking Files
1. Navigate to "Create Watermark" from the dashboard
2. Upload a file (supported formats: JPEG, PNG, PDF)
3. Submit to apply watermark
4. Download the watermarked file

### Verifying Files
1. Navigate to "Verify File" from the dashboard
2. Upload a file to check for watermarks
3. View verification results showing ownership and integrity status

## System Requirements

### Hardware Requirements
- Processor: Intel Core i3 (8th Gen) / AMD Ryzen 3 (or better)
- RAM: 4 GB (minimum), 8 GB (recommended)
- Storage: 500 MB free space
- Internet connection

### Software Requirements
- Operating System: Windows 10/11, macOS 10.15+, Ubuntu 20.04+
- Python 3.9 or higher
- Modern web browser (Chrome, Firefox, Safari, Edge)

## Project Structure

```
aquaguard/
├── app.py                  # Application entry point
├── config.py               # Configuration settings
├── requirements.txt        # Project dependencies
├── aquaguard/
│   ├── __init__.py         # Application factory
│   ├── models/             # Database models
│   ├── routes/             # Route definitions
│   ├── static/             # Static assets
│   │   ├── css/            # Stylesheets
│   │   ├── js/             # JavaScript files
│   │   └── images/         # Images
│   ├── templates/          # HTML templates
│   │   ├── auth/           # Authentication templates
│   │   ├── watermark/      # Watermarking templates
│   │   └── verification/   # Verification templates
│   └── utils/              # Utility functions
└── migrations/             # Database migrations
```

## Security Features

- **Invisible Watermarking**: Embeds ownership information without visible alterations
- **Encryption**: Secures watermark data with AES-256 encryption
- **Integrity Verification**: Detects any modifications to protected files
- **Secure Authentication**: Implements SHA-3 password hashing
- **CSRF Protection**: Prevents cross-site request forgery attacks

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- Flask Documentation
- Bootstrap Documentation
- Cryptography.io
- Pillow (PIL Fork) Documentation