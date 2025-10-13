from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import login_required, current_user
from ..models.watermark import Watermark
from ..utils.db import db
from ..utils.watermark import WatermarkGenerator
import os
from werkzeug.utils import secure_filename
import uuid

verification_bp = Blueprint('verification', __name__, url_prefix='/verify')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image_file(filename):
    IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in IMAGE_EXTENSIONS

def is_pdf_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'

@verification_bp.route('/', methods=['GET', 'POST'])
def verify_file():
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
            temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp', unique_filename)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(temp_path), exist_ok=True)
            
            # Save file
            file.save(temp_path)
            
            # Calculate file hash
            file_hash = WatermarkGenerator.calculate_file_hash(temp_path)
            
            # Check if file hash exists in database
            watermark = Watermark.query.filter_by(file_hash=file_hash).first()
            
            if watermark:
                # File hash matches, try to extract watermark based on file type
                try:
                    extracted_data = None
                    if is_image_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_lsb(temp_path, watermark.encryption_key)
                    elif is_pdf_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_pdf(temp_path, watermark.encryption_key)
                    
                    if extracted_data:
                        # Watermark successfully extracted
                        verification_result = {
                            'status': 'success',
                            'message': 'Watermark successfully verified',
                            'owner': extracted_data.get('user_email'),
                            'timestamp': extracted_data.get('timestamp'),
                            'filename': extracted_data.get('filename'),
                            'integrity': 'Intact'
                        }
                    else:
                        # Watermark extraction failed
                        verification_result = {
                            'status': 'warning',
                            'message': 'File hash matches but watermark extraction failed',
                            'integrity': 'Compromised'
                        }
                except Exception as e:
                    verification_result = {
                        'status': 'error',
                        'message': f'Error extracting watermark: {str(e)}',
                        'integrity': 'Unknown'
                    }
            else:
                # Try to extract watermark from all watermarks
                all_watermarks = Watermark.query.all()
                found = False
                
                for wm in all_watermarks:
                    try:
                        extracted_data = None
                        if is_image_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_lsb(temp_path, wm.encryption_key)
                        elif is_pdf_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_pdf(temp_path, wm.encryption_key)
                        
                        if extracted_data:
                            # Watermark found but hash doesn't match
                            verification_result = {
                                'status': 'warning',
                                'message': 'Watermark found but file has been modified',
                                'owner': extracted_data.get('user_email'),
                                'timestamp': extracted_data.get('timestamp'),
                                'filename': extracted_data.get('filename'),
                                'integrity': 'Modified'
                            }
                            found = True
                            break
                    except:
                        continue
                
                if not found:
                    verification_result = {
                        'status': 'error',
                        'message': 'No watermark found in this file',
                        'integrity': 'Not Protected'
                    }
            
            # Clean up temp file
            os.remove(temp_path)
            
            return render_template('verification/result.html', result=verification_result)
        else:
            flash('File type not allowed', 'danger')
            return redirect(request.url)
    
    return render_template('verification/verify.html')

@verification_bp.route('/api', methods=['POST'])
def verify_api():
    # Similar to verify_file but returns JSON response
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'})
    
    if file and allowed_file(file.filename):
        # Process file and verify watermark
        # (Similar logic to verify_file)
        
        # Return JSON response
        return jsonify(verification_result)
    else:
        return jsonify({'status': 'error', 'message': 'File type not allowed'})