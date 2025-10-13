from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, send_file
from flask_login import login_required, current_user
from ..models.watermark import Watermark
from ..utils.db import db
from ..utils.watermark import WatermarkGenerator
import os
import uuid
import datetime
from werkzeug.utils import secure_filename

watermark_bp = Blueprint('watermark', __name__, url_prefix='/watermark')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image_file(filename):
    IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in IMAGE_EXTENSIONS

def is_pdf_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'

@watermark_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_watermark():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()
            
            # Generate unique filename
            unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
            original_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'original', unique_filename)
            watermarked_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'watermarked', unique_filename)
            
            # Ensure directories exist
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            os.makedirs(os.path.dirname(watermarked_path), exist_ok=True)
            
            # Save original file
            file.save(original_path)
            
            # Generate watermark data
            watermark_data = {
                'user_id': current_user.id,
                'user_email': current_user.email,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'filename': filename,
                'unique_id': uuid.uuid4().hex
            }
            
            # Generate encryption key
            encryption_key = WatermarkGenerator.generate_encryption_key()
            
            # Calculate file hash
            file_hash = WatermarkGenerator.calculate_file_hash(original_path)
            
            # Embed watermark based on file type
            try:
                if is_image_file(filename):
                    WatermarkGenerator.embed_watermark_lsb(original_path, watermark_data, watermarked_path, encryption_key)
                elif is_pdf_file(filename):
                    WatermarkGenerator.embed_watermark_pdf(original_path, watermark_data, watermarked_path, encryption_key)
                else:
                    flash('Unsupported file type', 'danger')
                    return redirect(request.url)
                
                # Save watermark info to database
                new_watermark = Watermark(
                    user_id=current_user.id,
                    file_name=filename,
                    original_file_path=original_path,
                    watermarked_file_path=watermarked_path,
                    file_hash=file_hash,
                    encryption_key=encryption_key,
                    file_type=file_ext
                )
                new_watermark.set_watermark_data(watermark_data)
                
                db.session.add(new_watermark)
                db.session.commit()
                
                flash('Watermark successfully created!', 'success')
                return redirect(url_for('dashboard'))
            
            except Exception as e:
                flash(f'Error creating watermark: {str(e)}', 'danger')
                return redirect(request.url)
        else:
            flash('File type not allowed', 'danger')
            return redirect(request.url)
    
    return render_template('watermark/create.html')

@watermark_bp.route('/view/<int:watermark_id>')
@login_required
def view_watermark(watermark_id):
    watermark = Watermark.query.get_or_404(watermark_id)
    
    # Ensure user owns this watermark
    if watermark.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('watermark/view.html', watermark=watermark)

@watermark_bp.route('/download/<int:watermark_id>')
@login_required
def download_watermark(watermark_id):
    watermark = Watermark.query.get_or_404(watermark_id)
    
    # Ensure user owns this watermark
    if watermark.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    # Return the watermarked file
    return send_file(watermark.watermarked_file_path, as_attachment=True, 
                    download_name=watermark.file_name)