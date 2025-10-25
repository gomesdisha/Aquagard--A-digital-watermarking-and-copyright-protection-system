# watermark_routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, send_file
from flask_login import login_required, current_user
from ..models.watermark import Watermark
from ..utils.db import db
from ..utils.watermark import WatermarkGenerator
import os
import uuid
import datetime
from werkzeug.utils import secure_filename
import logging

logger = logging.getLogger(__name__)
watermark_bp = Blueprint('watermark', __name__, url_prefix='/watermark')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'pdf', 'wav', 'mp3', 'mp4', 'avi', 'mov', 'mkv', 'docx', 'xlsx', 'pptx'}
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
AUDIO_EXTENSIONS = {'wav', 'mp3'}
VIDEO_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in IMAGE_EXTENSIONS

def is_pdf_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'

def is_audio_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in AUDIO_EXTENSIONS

def is_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in VIDEO_EXTENSIONS

def is_docx_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'docx'

def is_xlsx_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'xlsx'

def is_pptx_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pptx'


@watermark_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_watermark():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('File type not allowed', 'danger')
            return redirect(request.url)

        try:
            # Secure original filename and pick extension
            filename = secure_filename(file.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()
            # Unique filenames used for storage to avoid collisions
            unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
            original_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'original')
            watermarked_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'watermarked')
            os.makedirs(original_dir, exist_ok=True)
            os.makedirs(watermarked_dir, exist_ok=True)
            original_path = os.path.join(original_dir, unique_filename)
            watermarked_path = os.path.join(watermarked_dir, unique_filename)

            # Save original file
            file.save(original_path)
            logger.info(f"Saved original to {original_path}")

            # Calculate hash BEFORE embedding (original file hash)
            file_hash = WatermarkGenerator.calculate_file_hash(original_path)
            logger.info(f"Original hash: {file_hash[:12]}...")

            watermark_data = {
                'user_id': current_user.id,
                'user_email': current_user.email,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'filename': filename,
                'unique_id': uuid.uuid4().hex,
                'original_hash': file_hash
            }

            # Get encryption key (string or bytes)
            encryption_key = WatermarkGenerator.generate_encryption_key()

            # Embed watermark according to type
            try:
                if is_image_file(filename):
                    WatermarkGenerator.embed_watermark_lsb(original_path, watermark_data, watermarked_path, encryption_key)
                elif is_pdf_file(filename):
                    WatermarkGenerator.embed_watermark_pdf(original_path, watermark_data, watermarked_path, encryption_key)
                elif is_audio_file(filename):
                    WatermarkGenerator.embed_watermark_audio(original_path, watermark_data, watermarked_path, encryption_key)
                elif is_video_file(filename):
                    WatermarkGenerator.embed_watermark_video(original_path, watermark_data, watermarked_path, encryption_key)
                elif is_docx_file(filename):
                    WatermarkGenerator.embed_watermark_docx(original_path, watermark_data, watermarked_path, encryption_key)
                elif is_xlsx_file(filename):
                    WatermarkGenerator.embed_watermark_xlsx(original_path, watermark_data, watermarked_path, encryption_key)
                elif is_pptx_file(filename):
                    WatermarkGenerator.embed_watermark_pptx(original_path, watermark_data, watermarked_path, encryption_key)
                else:
                    flash('Unsupported file type for embedding', 'danger')
                    return redirect(request.url)
            except Exception as embed_err:
                logger.exception("Embedding failed")
                flash(f'Error embedding watermark: {str(embed_err)}', 'danger')
                # remove original file if you want or keep for debugging
                return redirect(request.url)

            # Save watermark record to DB
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

            try:
                db.session.add(new_watermark)
                db.session.commit()
                logger.info(f"Watermark DB entry created id={new_watermark.id}")
                flash('Watermark successfully created!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as db_error:
                db.session.rollback()
                logger.exception("Database save failed")
                flash(f'Error saving watermark to database: {str(db_error)}', 'danger')
                return redirect(request.url)
        except Exception as e:
            logger.exception("Unexpected error in create_watermark")
            flash(f'Unexpected error: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template('watermark/create.html')


@watermark_bp.route('/view/<int:watermark_id>')
@login_required
def view_watermark(watermark_id):
    watermark = Watermark.query.get_or_404(watermark_id)
    if watermark.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('watermark/view.html', watermark=watermark)


@watermark_bp.route('/download/<int:watermark_id>')
@login_required
def download_watermark(watermark_id):
    watermark = Watermark.query.get_or_404(watermark_id)
    if watermark.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    return send_file(
        watermark.watermarked_file_path,
        as_attachment=True,
        download_name=watermark.file_name
    )
