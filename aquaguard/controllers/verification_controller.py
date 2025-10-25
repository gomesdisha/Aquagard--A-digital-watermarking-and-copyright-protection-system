import os
import uuid
import logging
import time
import json
import base64
import binascii
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from werkzeug.utils import secure_filename
from aquaguard.models.watermark import Watermark
from aquaguard.utils.watermark import WatermarkGenerator

logger = logging.getLogger(__name__)
verification_bp = Blueprint('verification', __name__, url_prefix='/verify')

# ------------------------------------------------------------------------
# Allowed extensions
# ------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'pdf', 'docx', 'xlsx', 'pptx', 'mp3', 'wav', 'mp4', 'avi', 'mov', 'mkv'}
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}
AUDIO_EXTENSIONS = {'mp3', 'wav'}
VIDEO_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}


# ------------------------------------------------------------------------
# File type helpers
# ------------------------------------------------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in IMAGE_EXTENSIONS


def is_pdf_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pdf'


def is_docx_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'docx'


def is_xlsx_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'xlsx'


def is_pptx_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'pptx'


def is_audio_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in AUDIO_EXTENSIONS


def is_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in VIDEO_EXTENSIONS


# ------------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------------
def _normalize_key_variants(key_value):
    """Generate possible key variants to handle encoding differences."""
    variants = []
    if key_value is None:
        return variants

    if isinstance(key_value, (bytes, bytearray)):
        return [bytes(key_value)]

    if isinstance(key_value, str):
        variants.append(key_value)
        try:
            variants.append(key_value.encode('utf-8'))
        except Exception:
            pass
        try:
            variants.append(base64.b64decode(key_value))
        except Exception:
            pass
        try:
            variants.append(binascii.unhexlify(key_value))
        except Exception:
            pass
    else:
        try:
            s = str(key_value)
            variants += [s, s.encode('utf-8')]
        except Exception:
            pass

    unique = []
    for v in variants:
        if v not in unique:
            unique.append(v)
    return unique


def _parse_extraction_result(result):
    """Ensure the watermark extraction result is parsed as a dict."""
    if result is None:
        return None
    if isinstance(result, dict):
        return result
    if isinstance(result, (bytes, bytearray)):
        try:
            text = result.decode('utf-8')
            return json.loads(text)
        except Exception:
            return {'data_b64': base64.b64encode(result).decode('ascii')}
    if isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {'data': result}
    return {'data': str(result)}


def extract_watermark_by_type(filename_hint, path, key_variant):
    """Call correct extraction function based on file extension."""
    try:
        ext = filename_hint.rsplit('.', 1)[1].lower() if '.' in filename_hint else ''
        if ext in IMAGE_EXTENSIONS:
            result = WatermarkGenerator.extract_watermark_lsb(path, key_variant)
        elif ext == 'pdf':
            result = WatermarkGenerator.extract_watermark_pdf(path, key_variant)
        elif ext == 'docx':
            result = WatermarkGenerator.extract_watermark_docx(path, key_variant)
        elif ext == 'xlsx':
            result = WatermarkGenerator.extract_watermark_xlsx(path, key_variant)
        elif ext == 'pptx':
            result = WatermarkGenerator.extract_watermark_pptx(path, key_variant)
        elif ext in AUDIO_EXTENSIONS:
            result = WatermarkGenerator.extract_watermark_audio(path, key_variant)
        elif ext in VIDEO_EXTENSIONS:
            result = WatermarkGenerator.extract_watermark_video(path, key_variant)
        else:
            logger.warning(f"Unsupported file type for extraction: {ext}")
            return None

        parsed = _parse_extraction_result(result)
        logger.debug(f"Extraction result parsed: {parsed}")
        return parsed
    except Exception as e:
        logger.exception(f"extract_watermark_by_type failed for {path}: {e}")
        return None


def build_result(status, message, extracted_data=None, integrity='Unknown'):
    """Builds structured verification result."""
    extracted_data = extracted_data or {}
    owner = extracted_data.get('user_email', 'Unknown')
    timestamp = extracted_data.get('timestamp', 'Unknown')
    filename = extracted_data.get('filename', 'Unknown')

    if integrity == 'Modified':
        owner = extracted_data.get('user_email', 'Original Owner Unknown')

    return {
        'status': status,
        'message': message,
        'owner': owner,
        'timestamp': timestamp,
        'filename': filename,
        'integrity': integrity
    }


# ------------------------------------------------------------------------
# Verification (Web)
# ------------------------------------------------------------------------
@verification_bp.route('/', methods=['GET', 'POST'])
def verify_file():
    """Handle file verification via web interface."""
    temp_path = None
    if request.method == 'POST':
        start_time = time.time()
        logger.info("🔍 Starting file verification process")

        # Basic file validation
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file uploaded or selected.', 'danger')
            return render_template('verification/result.html', result={'status': 'error', 'message': 'No file provided'})

        if not allowed_file(file.filename):
            flash('Unsupported file type.', 'danger')
            return render_template('verification/result.html', result={'status': 'error', 'message': 'Unsupported file type'})

        try:
            filename = secure_filename(file.filename)
            file_ext = filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
            temp_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, unique_filename)
            file.save(temp_path)
            logger.info(f"File saved temporarily at {temp_path}")

            file_hash = WatermarkGenerator.calculate_file_hash(temp_path)

            extracted_data = None
            matching_watermark = None
            MAX_KEYS = 20
            TIME_BUDGET_SECONDS = 5.0
            start_loop = time.time()

            recent_watermarks = (Watermark.query
                                 .filter(Watermark.file_type == file_ext)
                                 .order_by(Watermark.id.desc())
                                 .limit(MAX_KEYS)
                                 .all())

            for watermark in recent_watermarks:
                if time.time() - start_loop > TIME_BUDGET_SECONDS:
                    logger.warning("Stopping extraction attempts due to time limit")
                    break
                try:
                    extracted = extract_watermark_by_type(filename, temp_path, watermark.encryption_key)
                    if extracted:
                        extracted_data = extracted
                        matching_watermark = watermark
                        break
                except Exception as e:
                    logger.debug(f"Extraction failed for key {watermark.id}: {str(e)}")

            # Evaluate integrity
            if extracted_data and matching_watermark:
                embedded_hash = extracted_data.get('original_hash')
                db_hash = matching_watermark.file_hash

                logger.info(
                    f"Verification Debug: embedded={embedded_hash[:12] if embedded_hash else 'None'} "
                    f"db={db_hash[:12]} file={file_hash[:12]}"
                )

                if embedded_hash and embedded_hash == db_hash:
                    result = build_result('success', '✅ Watermark verified successfully — File is intact', extracted_data, 'Intact')
                    logger.info("File integrity verified (Intact)")
                else:
                    if is_image_file(filename):
                        result = build_result('warning', '🖌️ Watermark found but image content was updated after watermarking', extracted_data, 'Updated')
                        logger.warning("File integrity changed (Updated content, watermark intact)")
                    else:
                        result = build_result('warning', '⚠️ Watermark found but embedded hash does not match original file hash', extracted_data, 'Modified')
                        logger.warning("File integrity mismatch (Modified)")
            else:
                result = build_result('info', 'ℹ️ No watermark found in this file', None, 'Not Protected')
                logger.info("No watermark found in file")

            logger.info(f"Verification completed in {time.time() - start_time:.2f}s")
            return render_template('verification/result.html', result=result)

        except Exception as e:
            logger.exception(f"Error during verification: {e}")
            flash('An unexpected error occurred during verification.', 'danger')
            return redirect(request.url)

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    return render_template('verification/verify.html')


# ------------------------------------------------------------------------
# Verification (API)
# ------------------------------------------------------------------------
@verification_bp.route('/api', methods=['POST'])
def verify_api():
    """API endpoint for file verification (JSON response)."""
    temp_path = None
    try:
        file = request.files.get('file')
        if not file or file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file uploaded or selected'})

        if not allowed_file(file.filename):
            return jsonify({'status': 'error', 'message': 'Unsupported file type'})

        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
        temp_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, unique_filename)
        file.save(temp_path)

        file_hash = WatermarkGenerator.calculate_file_hash(temp_path)

        extracted_data = None
        matching_watermark = None
        MAX_KEYS = 20
        TIME_BUDGET_SECONDS = 5.0
        start_loop = time.time()

        recent_watermarks = (Watermark.query
                             .filter(Watermark.file_type == file_ext)
                             .order_by(Watermark.id.desc())
                             .limit(MAX_KEYS)
                             .all())

        for watermark in recent_watermarks:
            if time.time() - start_loop > TIME_BUDGET_SECONDS:
                break
            try:
                extracted = extract_watermark_by_type(filename, temp_path, watermark.encryption_key)
                if extracted:
                    extracted_data = extracted
                    matching_watermark = watermark
                    break
            except Exception:
                continue

        if extracted_data and matching_watermark:
            embedded_hash = extracted_data.get('original_hash')
            db_hash = matching_watermark.file_hash

            logger.info(f"[API] embedded={embedded_hash[:12] if embedded_hash else 'None'} db={db_hash[:12]} file={file_hash[:12]}")

            if embedded_hash and embedded_hash == db_hash:
                result = build_result('success', '✅ Watermark verified successfully — File is intact', extracted_data, 'Intact')
                logger.info("File integrity verified via API (Intact)")
            else:
                if is_image_file(filename):
                    result = build_result('warning', '🖌️ Watermark found but image content was updated after watermarking', extracted_data, 'Updated')
                    logger.warning("API: File integrity changed (Updated content, watermark intact)")
                else:
                    result = build_result('warning', '⚠️ Watermark found but embedded hash does not match original file hash', extracted_data, 'Modified')
                    logger.warning("API: File integrity mismatch (Modified)")
        else:
            result = build_result('info', 'ℹ️ No watermark found in this file', None, 'Not Protected')
            logger.info("API: No watermark found in file")

        return jsonify(result)

    except Exception as e:
        logger.exception(f"Error in verify_api: {e}")
        return jsonify({'status': 'error', 'message': str(e), 'integrity': 'Unknown'})

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
