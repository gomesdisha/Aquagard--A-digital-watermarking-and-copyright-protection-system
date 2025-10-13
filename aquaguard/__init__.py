from flask import Flask, render_template
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
import os

from .utils.db import db
from .models.user import User

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-aquaguard')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///aquaguard.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
    
    # Ensure upload directories exist
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'original'), exist_ok=True)
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'watermarked'), exist_ok=True)
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'temp'), exist_ok=True)
    
    # Initialize database
    db.init_app(app)
    
    # Initialize login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register blueprints
    from .controllers.auth_controller import auth
    from .controllers.watermark_controller import watermark_bp
    from .controllers.verification_controller import verification_bp
    
    app.register_blueprint(auth)
    app.register_blueprint(watermark_bp)
    app.register_blueprint(verification_bp)
    
    # Main routes
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/dashboard')
    def dashboard():
        if not current_user.is_authenticated:
            return render_template('index.html')
        
        from aquaguard.models.watermark import Watermark
        watermarks = Watermark.query.filter_by(user_id=current_user.id).all()
        
        # Calculate statistics
        total_files = len(watermarks)
        image_files = sum(1 for w in watermarks if w.file_type.lower() in ['jpg', 'jpeg', 'png', 'gif'])
        pdf_files = sum(1 for w in watermarks if w.file_type.lower() == 'pdf')
        
        return render_template('dashboard.html', 
                              watermarks=watermarks,
                              stats={
                                  'total': total_files,
                                  'images': image_files,
                                  'pdfs': pdf_files
                              })
    
    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
    
    return app