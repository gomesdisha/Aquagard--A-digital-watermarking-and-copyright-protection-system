import os
import uuid
import logging
import time
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from werkzeug.utils import secure_filename
from aquaguard.models.watermark import Watermark
from aquaguard.utils.watermark import WatermarkGenerator

# Configure logger
logger = logging.getLogger(__name__)

verification_bp = Blueprint('verification', __name__, url_prefix='/verify')

def allowed_file(filename):
    """Check if file has an allowed extension"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'xlsx', 'pptx', 'mp3', 'wav', 'mp4', 'avi', 'mov'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image_file(filename):
    """Check if file is an image"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def is_pdf_file(filename):
    """Check if file is a PDF"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'

def is_docx_file(filename):
    """Check if file is a DOCX"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'docx'

def is_xlsx_file(filename):
    """Check if file is an XLSX"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'xlsx'

def is_pptx_file(filename):
    """Check if file is a PPTX"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pptx'

def is_audio_file(filename):
    """Check if file is an audio file"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'mp3', 'wav'}

def is_video_file(filename):
    """Check if file is a video file"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'mp4', 'avi', 'mov'}

@verification_bp.route('/', methods=['GET', 'POST'])
def verify_file():
    """Handle file verification"""
    if request.method == 'POST':
        start_time = time.time()
        logger.info("Starting file verification process")
        
        # Check if the post request has the file part
        if 'file' not in request.files:
            logger.warning("No file part in request")
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            logger.warning("No selected file")
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if not allowed_file(file.filename):
            logger.warning(f"File type not allowed: {file.filename}")
            flash('File type not allowed', 'danger')
            return redirect(request.url)
        
        temp_path = None
        try:
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
            logger.info(f"File saved temporarily as {temp_path}")
        except Exception as e:
            logger.error(f"File processing error: {str(e)}", exc_info=True)
            flash(f'Error processing file: {str(e)}', 'danger')
            return redirect(request.url)
        
        try:
            # Calculate file hash
            file_hash = WatermarkGenerator.calculate_file_hash(temp_path)
            logger.info(f"File hash calculated: {file_hash[:10]}...")
            
            # Check if file hash exists in database
            watermark = Watermark.query.filter_by(file_hash=file_hash).first()
            
            if watermark:
                logger.info(f"Watermark found in database for hash {file_hash[:10]}...")
                # Extract watermark based on file type
                extracted_data = None
                is_modified = False
                
                try:
                    if is_image_file(filename):
                        logger.info("Extracting watermark from image file")
                        extracted_data = WatermarkGenerator.extract_watermark_lsb(temp_path, watermark.encryption_key)
                    elif is_pdf_file(filename):
                        logger.info("Extracting watermark from PDF file")
                        extracted_data = WatermarkGenerator.extract_watermark_pdf(temp_path, watermark.encryption_key)
                    elif is_docx_file(filename):
                        logger.info("Extracting watermark from DOCX file")
                        extracted_data = WatermarkGenerator.extract_watermark_docx(temp_path, watermark.encryption_key)
                    elif is_xlsx_file(filename):
                        logger.info("Extracting watermark from XLSX file")
                        extracted_data = WatermarkGenerator.extract_watermark_xlsx(temp_path, watermark.encryption_key)
                    elif is_pptx_file(filename):
                        logger.info("Extracting watermark from PPTX file")
                        extracted_data = WatermarkGenerator.extract_watermark_pptx(temp_path, watermark.encryption_key)
                    elif is_audio_file(filename):
                        logger.info("Extracting watermark from audio file")
                        extracted_data = WatermarkGenerator.extract_watermark_audio(temp_path, watermark.encryption_key)
                    elif is_video_file(filename):
                        logger.info("Extracting watermark from video file")
                        extracted_data = WatermarkGenerator.extract_watermark_video(temp_path, watermark.encryption_key)
                except Exception as e:
                    logger.error(f"Error extracting watermark: {str(e)}", exc_info=True)
                    extracted_data = None
                
                if extracted_data:
                    logger.info("Watermark extracted successfully")
                    # Check if the file has been modified
                    if is_image_file(filename):
                        # For images, we can check if the extracted watermark matches the original
                        if extracted_data.get('file_hash') != file_hash:
                            is_modified = True
                            logger.warning("File appears to be modified (hash mismatch)")
                    
                    # Clean up temp file
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                            logger.info("Temporary file removed")
                    except Exception as e:
                        logger.error(f"Error removing temp file: {str(e)}", exc_info=True)
                    
                    result = {
                        'status': 'success',
                        'message': 'Watermark successfully verified',
                        'owner': extracted_data.get('user_email'),
                        'timestamp': extracted_data.get('timestamp'),
                        'filename': extracted_data.get('filename'),
                        'integrity': 'Modified' if is_modified else 'Intact'
                    }
                    
                    elapsed_time = time.time() - start_time
                    logger.info(f"Verification completed successfully in {elapsed_time:.2f} seconds")
                    return render_template('verification/result.html', result=result)
                else:
                    logger.warning("File hash matches but watermark extraction failed")
                    # Clean up temp file
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                            logger.info("Temporary file removed")
                    except Exception as e:
                        logger.error(f"Error removing temp file: {str(e)}", exc_info=True)
                    
                    result = {
                        'status': 'warning',
                        'message': 'File hash matches but watermark extraction failed',
                        'owner': watermark.user.email if hasattr(watermark, 'user') and watermark.user is not None else 'Unknown',
                        'timestamp': str(watermark.timestamp) if hasattr(watermark, 'timestamp') else 'Unknown',
                        'filename': watermark.filename if hasattr(watermark, 'filename') else os.path.basename(file.filename),
                        'integrity': 'Compromised'
                    }
                    
                    elapsed_time = time.time() - start_time
                    logger.info(f"Verification completed with warnings in {elapsed_time:.2f} seconds")
                    return render_template('verification/result.html', result=result)
            else:
                # Try to extract watermark from most likely watermarks first
                # Get watermarks with same file extension first for faster matching
                logger.info(f"No watermark found by hash, trying to match by extraction for file type: {file_ext}")
                
                # Optimize watermark matching by prioritizing recent watermarks of the same file type
                file_type_watermarks = Watermark.query.filter(Watermark.file_type == file_ext).order_by(Watermark.id.desc()).limit(5).all()
                logger.info(f"Found {len(file_type_watermarks)} potential watermarks of the same file type")
                
                # Get a small number of other watermarks as fallback
                other_watermarks = Watermark.query.filter(Watermark.file_type != file_ext).order_by(Watermark.id.desc()).limit(3).all()
                
                # Combine and limit to most recent watermarks for performance
                all_watermarks = file_type_watermarks + other_watermarks
                logger.info(f"Attempting extraction with {len(all_watermarks)} watermarks")
                
                found = False
                
                for wm in all_watermarks:
                    try:
                        extracted_data = None
                        logger.info(f"Trying extraction with watermark ID: {wm.id}")
                        
                        # Only try extraction method that matches file type
                        if is_image_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_lsb(temp_path, wm.encryption_key)
                        elif is_pdf_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_pdf(temp_path, wm.encryption_key)
                        elif is_docx_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_docx(temp_path, wm.encryption_key)
                        elif is_xlsx_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_xlsx(temp_path, wm.encryption_key)
                        elif is_pptx_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_pptx(temp_path, wm.encryption_key)
                        elif is_audio_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_audio(temp_path, wm.encryption_key)
                        elif is_video_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_video(temp_path, wm.encryption_key)
                        
                        if extracted_data:
                            found = True
                            logger.info(f"Watermark successfully extracted with watermark ID: {wm.id}")
                            # Clean up temp file
                            try:
                                if os.path.exists(temp_path):
                                    os.remove(temp_path)
                                    logger.info("Temporary file removed")
                            except Exception as e:
                                logger.error(f"Error removing temp file: {str(e)}", exc_info=True)
                            
                            result = {
                                'status': 'success',
                                'message': 'Watermark successfully verified',
                                'owner': extracted_data.get('user_email'),
                                'timestamp': extracted_data.get('timestamp'),
                                'filename': extracted_data.get('filename'),
                                'integrity': 'Intact'
                            }
                            
                            elapsed_time = time.time() - start_time
                            logger.info(f"Verification completed successfully in {elapsed_time:.2f} seconds")
                            return render_template('verification/result.html', result=result)
                    except Exception as e:
                        logger.warning(f"Failed extraction attempt with watermark ID {wm.id}: {str(e)}")
                        continue
                    
                # If we get here, no watermark was found
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                        logger.info("Temporary file removed")
                except Exception as e:
                    logger.error(f"Error removing temp file: {str(e)}", exc_info=True)
                
                result = {
                    'status': 'warning',
                    'message': 'No watermark found in this file',
                    'integrity': 'Not Protected'
                }
                
                elapsed_time = time.time() - start_time
                logger.info(f"Verification completed with warning in {elapsed_time:.2f} seconds - No watermark found")
                flash('No watermark found in this file', 'warning')
                return render_template('verification/result.html', result=result)
        except Exception as e:
            # Handle any unexpected errors during verification
            logger.error(f"Unexpected error during verification: {str(e)}", exc_info=True)
            
            # Clean up temp file if it exists
            try:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)
                    logger.info("Temporary file removed")
            except Exception as cleanup_error:
                logger.error(f"Error removing temp file: {str(cleanup_error)}", exc_info=True)
            
            flash('An error occurred during verification. Please try again.', 'danger')
            return redirect(request.url)
    
    return render_template('verification/verify.html')

@verification_bp.route('/api', methods=['POST'])
def verify_api():
    """API endpoint for file verification"""
    logger.info("API verification request received")
    if 'file' not in request.files:
        logger.warning("API request missing file part")
        return jsonify({'status': 'error', 'message': 'No file part'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'})
    
    if file and allowed_file(file.filename):
        # Secure the filename
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower()
        
        # Generate unique filename
        unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
        temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp', unique_filename)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        
        try:
            # Save file
            file.save(temp_path)
            
            # Calculate file hash
            file_hash = WatermarkGenerator.calculate_file_hash(temp_path)
            
            # Check if file hash exists in database
            watermark = Watermark.query.filter_by(file_hash=file_hash).first()
            
            if watermark:
                # Extract watermark based on file type
                extracted_data = None
                is_modified = False
                
                try:
                    if is_image_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_lsb(temp_path, watermark.encryption_key)
                    elif is_pdf_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_pdf(temp_path, watermark.encryption_key)
                    elif is_docx_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_docx(temp_path, watermark.encryption_key)
                    elif is_xlsx_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_xlsx(temp_path, watermark.encryption_key)
                    elif is_pptx_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_pptx(temp_path, watermark.encryption_key)
                    elif is_audio_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_audio(temp_path, watermark.encryption_key)
                    elif is_video_file(filename):
                        extracted_data = WatermarkGenerator.extract_watermark_video(temp_path, watermark.encryption_key)
                    
                    if extracted_data and is_image_file(filename):
                        # For images, check if the extracted watermark matches the original
                        if extracted_data.get('file_hash') != file_hash:
                            is_modified = True
                except Exception as e:
                    print(f"Error extracting watermark: {str(e)}")
                    extracted_data = None
                
                if extracted_data:
                    result = {
                        'status': 'success',
                        'message': 'Watermark successfully verified',
                        'owner': extracted_data.get('user_email'),
                        'timestamp': extracted_data.get('timestamp'),
                        'filename': extracted_data.get('filename'),
                        'integrity': 'Modified' if is_modified else 'Intact'
                    }
                else:
                    result = {
                        'status': 'warning',
                        'message': 'File hash matches but watermark extraction failed',
                        'owner': watermark.user.email if hasattr(watermark, 'user') and watermark.user is not None else 'Unknown',
                        'timestamp': str(watermark.timestamp) if hasattr(watermark, 'timestamp') else 'Unknown',
                        'filename': watermark.filename if hasattr(watermark, 'filename') else os.path.basename(file.filename),
                        'integrity': 'Compromised'
                    }
            else:
                # Try to extract watermark from most likely watermarks first
                # Get watermarks with same file extension first for faster matching
                file_type_watermarks = Watermark.query.filter(Watermark.file_type == file_ext).all()
                
                # Limit to 5 most recent watermarks for performance
                file_type_watermarks = file_type_watermarks[:5]
                
                found = False
                result = {'status': 'error', 'message': 'No watermark found', 'integrity': 'Not Protected'}
                
                for wm in file_type_watermarks:
                    try:
                        extracted_data = None
                        
                        # Only try extraction method that matches file type
                        if is_image_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_lsb(temp_path, wm.encryption_key)
                        elif is_pdf_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_pdf(temp_path, wm.encryption_key)
                        elif is_docx_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_docx(temp_path, wm.encryption_key)
                        elif is_xlsx_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_xlsx(temp_path, wm.encryption_key)
                        elif is_pptx_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_pptx(temp_path, wm.encryption_key)
                        elif is_audio_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_audio(temp_path, wm.encryption_key)
                        elif is_video_file(filename):
                            extracted_data = WatermarkGenerator.extract_watermark_video(temp_path, wm.encryption_key)
                        
                        if extracted_data:
                            found = True
                            result = {
                                'status': 'success',
                                'message': 'Watermark successfully verified',
                                'owner': extracted_data.get('user_email'),
                                'timestamp': extracted_data.get('timestamp'),
                                'filename': extracted_data.get('filename'),
                                'integrity': 'Intact'
                            }
                            break
                    except Exception as e:
                        print(f"Error trying watermark key {wm.id}: {str(e)}")
                        continue
                
                if not found:
                    result = {
                        'status': 'error',
                        'message': 'No watermark found in this file',
                        'integrity': 'Not Protected'
                    }
            
            return jsonify(result)
            
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Error during verification: {str(e)}',
                'integrity': 'Unknown'
            })
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
    else:
        return jsonify({'status': 'error', 'message': 'File type not allowed'})