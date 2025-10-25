from PIL import Image
import os
import json
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import numpy as np
import PyPDF2
from reportlab.pdfgen import canvas
from io import BytesIO

class WatermarkGenerator:
    @staticmethod
    def generate_encryption_key():
        """Generate a random AES-256 key"""
        return secrets.token_hex(32)  # 32 bytes = 256 bits
    
    @staticmethod
    def encrypt_data(data, key):
        """Encrypt data using AES-256"""
        # Convert string key to bytes
        key_bytes = bytes.fromhex(key)
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create cipher
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        
        # Convert data to JSON string and then to bytes
        data_bytes = json.dumps(data).encode('utf-8')
        
        # Pad data to block size
        padded_data = pad(data_bytes, AES.block_size)
        
        # Encrypt
        encrypted_data = cipher.encrypt(padded_data)
        
        # Combine IV and encrypted data and encode as base64
        result = base64.b64encode(iv + encrypted_data).decode('utf-8')
        
        return result
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Decrypt data using AES-256"""
        try:
            # Convert key from hex to bytes
            key_bytes = bytes.fromhex(key)
            
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Extract IV (first 16 bytes)
            iv = encrypted_bytes[:16]
            actual_encrypted_data = encrypted_bytes[16:]
            
            # Create cipher
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            
            # Decrypt and unpad
            decrypted_data = unpad(cipher.decrypt(actual_encrypted_data), AES.block_size)
            
            # Convert bytes to JSON
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate SHA-3 hash of a file"""
        sha3_hash = hashlib.sha3_256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha3_hash.update(chunk)
        return sha3_hash.hexdigest()
    
    @staticmethod
    def embed_watermark_lsb(image_path, watermark_data, output_path, encryption_key):
        """Embed watermark using LSB steganography"""
        try:
            # Open image
            img = Image.open(image_path)
            
            # Convert to RGB mode if not already
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            img_array = np.array(img)
            
            # Encrypt watermark data
            encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
            
            # Convert encrypted data to binary with proper encoding
            binary_data = ''.join(format(byte, '08b') for byte in encrypted_data.encode('utf-8'))
            
            # Add length prefix (32 bits) and end marker (8 bits)
            length_prefix = format(len(binary_data), '032b')
            binary_data = length_prefix + binary_data + '11111111'  # End marker (8 ones)
            
            # Check if image has enough pixels to store the watermark
            required_pixels = len(binary_data)
            available_pixels = img.width * img.height * 3  # RGB channels
            
            if available_pixels < required_pixels:
                raise ValueError(f"Image too small to embed the watermark. Required: {required_pixels}, Available: {available_pixels}")
            
            # Embed data in LSB
            data_index = 0
            for i in range(img_array.shape[0]):
                for j in range(img_array.shape[1]):
                    for k in range(3):  # RGB channels
                        if data_index < len(binary_data):
                            # Replace LSB with watermark bit
                            img_array[i, j, k] = (img_array[i, j, k] & 254) | int(binary_data[data_index])
                            data_index += 1
                        else:
                            break
                    if data_index >= len(binary_data):
                        break
                if data_index >= len(binary_data):
                    break
                    
            # Save watermarked image
            watermarked_img = Image.fromarray(img_array.astype(np.uint8))
            watermarked_img.save(output_path)
            
        except Exception as e:
            raise Exception(f"Error embedding watermark: {str(e)}")
        
    @staticmethod
    def extract_watermark_lsb(image_path, encryption_key):
        """Extract watermark from image using LSB steganography"""
        try:
            # Open image
            img = Image.open(image_path)
            
            # Convert to RGB mode if not already
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            img_array = np.array(img)
            
            # Extract binary data from LSB with early stopping
            bits = []
            total_needed = None  # 32 (length) + payload + 8 (end marker)
            done = False
            for i in range(img_array.shape[0]):
                if done:
                    break
                for j in range(img_array.shape[1]):
                    if done:
                        break
                    for k in range(3):  # RGB channels
                        bits.append('1' if (img_array[i, j, k] & 1) else '0')
                        # Once we have the 32-bit length prefix, compute total bits needed
                        if total_needed is None and len(bits) >= 32:
                            length_binary = ''.join(bits[:32])
                            try:
                                data_length = int(length_binary, 2)
                            except ValueError:
                                return None
                            total_needed = 32 + data_length + 8
                        # Stop once we have all required bits
                        if total_needed is not None and len(bits) >= total_needed:
                            done = True
                            break
            
            if total_needed is None or len(bits) < total_needed:
                return None
            
            binary_data = ''.join(bits)
            data_binary = binary_data[32:32 + data_length]
            end_marker = binary_data[32 + data_length:32 + data_length + 8]
            
            # Verify end marker
            if end_marker != '11111111':
                return None
            
            # Convert binary to bytes
            try:
                encrypted_bytes = bytearray()
                for idx in range(0, len(data_binary), 8):
                    if idx + 8 <= len(data_binary):
                        byte = data_binary[idx:idx+8]
                        encrypted_bytes.append(int(byte, 2))
                
                # Convert to string - handle potential encoding issues
                try:
                    encrypted_data = encrypted_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    # If UTF-8 fails, try latin-1 which can handle any byte value
                    encrypted_data = encrypted_bytes.decode('latin-1')
                
                # Decrypt data
                return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
                
            except (ValueError, UnicodeDecodeError) as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error converting binary data: {str(e)}", exc_info=True)
                return None
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error extracting watermark from image: {str(e)}", exc_info=True)
            return None
        
    @staticmethod
    def embed_watermark_pdf(pdf_path, watermark_data, output_path, encryption_key):
        """Embed watermark in PDF metadata"""
        # Encrypt watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Open PDF
        pdf_reader = PyPDF2.PdfReader(pdf_path)
        pdf_writer = PyPDF2.PdfWriter()
        
        # Copy all pages
        for page_num in range(len(pdf_reader.pages)):
            pdf_writer.add_page(pdf_reader.pages[page_num])
        
        # Add encrypted watermark to metadata
        pdf_writer.add_metadata({
            "/AquaGuardWatermark": encrypted_data
        })
        
        # Save watermarked PDF
        with open(output_path, "wb") as f:
            pdf_writer.write(f)
            
    @staticmethod
    def extract_watermark_pdf(pdf_path, encryption_key):
        """Extract watermark from PDF metadata"""
        try:
            # Open PDF
            pdf_reader = PyPDF2.PdfReader(pdf_path)
            
            # Get metadata
            metadata = pdf_reader.metadata
            
            # Check if watermark exists
            if metadata and "/AquaGuardWatermark" in metadata:
                encrypted_data = metadata["/AquaGuardWatermark"]
                return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
            
            return None
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error extracting watermark from PDF: {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def embed_watermark_video(video_path, watermark_data, output_path, encryption_key):
        """Embed watermark in video metadata"""
        # Encrypt watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Read the video file
        with open(video_path, 'rb') as f:
            video_data = f.read()
        
        # Create a simple metadata format: AQUAGUARD_WATERMARK:encrypted_data
        metadata_marker = b'AQUAGUARD_WATERMARK:'
        metadata_content = metadata_marker + encrypted_data.encode('utf-8')
        
        # Append metadata to the end of the video file
        with open(output_path, 'wb') as f:
            f.write(video_data)
            f.write(metadata_content)
    
    @staticmethod
    def extract_watermark_video(video_path, encryption_key):
        """Extract watermark from video metadata"""
        try:
            # Read the video file
            with open(video_path, 'rb') as f:
                video_data = f.read()
            
            # Look for the metadata marker
            metadata_marker = b'AQUAGUARD_WATERMARK:'
            marker_index = video_data.find(metadata_marker)
            
            if marker_index == -1:
                return None
            
            # Extract the encrypted data
            encrypted_data_start = marker_index + len(metadata_marker)
            encrypted_data = video_data[encrypted_data_start:].decode('utf-8', errors='ignore')
            
            # Decrypt the data
            return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error extracting watermark from video: {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def embed_watermark_audio(audio_path, watermark_data, output_path, encryption_key):
        """Embed watermark in audio metadata"""
        # Encrypt watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Read the audio file
        with open(audio_path, 'rb') as f:
            audio_data = f.read()
        
        # Create a simple metadata format: AQUAGUARD_WATERMARK:encrypted_data
        metadata_marker = b'AQUAGUARD_WATERMARK:'
        metadata_content = metadata_marker + encrypted_data.encode('utf-8')
        
        # Append metadata to the end of the audio file
        with open(output_path, 'wb') as f:
            f.write(audio_data)
            f.write(metadata_content)
    
    @staticmethod
    def extract_watermark_audio(audio_path, encryption_key):
        """Extract watermark from audio metadata"""
        try:
            # Read the audio file
            with open(audio_path, 'rb') as f:
                audio_data = f.read()
            
            # Look for the metadata marker
            metadata_marker = b'AQUAGUARD_WATERMARK:'
            marker_index = audio_data.find(metadata_marker)
            
            if marker_index == -1:
                return None
            
            # Extract the encrypted data
            encrypted_data_start = marker_index + len(metadata_marker)
            encrypted_data = audio_data[encrypted_data_start:].decode('utf-8', errors='ignore')
            
            # Decrypt the data
            return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error extracting watermark from audio: {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def embed_watermark_docx(docx_path, watermark_data, output_path, encryption_key):
        """Embed watermark in DOCX file as custom property"""
        # Import required libraries
        from docx import Document
        from docx.opc.constants import RELATIONSHIP_TYPE as RT
        from docx.opc.part import PartFactory
        from docx.opc.packuri import PackURI
        from docx.opc.rel import RelationshipItem
        
        # Encrypt watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Copy the original file to output path
        import shutil
        shutil.copy2(docx_path, output_path)
        
        # Open the document
        doc = Document(output_path)
        
        # Add custom property with encrypted watermark
        core_props = doc.core_properties
        app_props = doc.part.package.part_related_by(RT.EXTENDED_PROPERTIES)
        
        # Add custom property
        app_props._element.set('AquaGuardWatermark', encrypted_data)
        
        # Save the document
        doc.save(output_path)
    
    @staticmethod
    def extract_watermark_docx(docx_path, encryption_key):
        """Extract watermark from DOCX file custom property"""
        try:
            # Import required libraries
            from docx import Document
            from docx.opc.constants import RELATIONSHIP_TYPE as RT
            
            # Open the document
            doc = Document(docx_path)
            
            # Get app properties
            app_props = doc.part.package.part_related_by(RT.EXTENDED_PROPERTIES)
            
            # Check if watermark exists
            if app_props._element.get('AquaGuardWatermark'):
                encrypted_data = app_props._element.get('AquaGuardWatermark')
                return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
            
            return None
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error extracting watermark from DOCX: {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def embed_watermark_xlsx(xlsx_path, watermark_data, output_path, encryption_key):
        """Embed watermark in XLSX file as document property"""
        # Import required libraries
        import openpyxl
        
        # Encrypt watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Copy the original file to output path
        import shutil
        shutil.copy2(xlsx_path, output_path)
        
        # Open the workbook
        wb = openpyxl.load_workbook(output_path)
        
        # Add custom property
        wb.properties.customProperties.append(['AquaGuardWatermark', encrypted_data])
        
        # Save the workbook
        wb.save(output_path)
    
    @staticmethod
    def extract_watermark_xlsx(xlsx_path, encryption_key):
        """Extract watermark from XLSX file document property"""
        try:
            # Import required libraries
            import openpyxl
            
            # Open the workbook
            wb = openpyxl.load_workbook(xlsx_path)
            
            # Check if watermark exists in custom properties
            for prop in wb.properties.customProperties:
                if prop[0] == 'AquaGuardWatermark':
                    encrypted_data = prop[1]
                    return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
            
            return None
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error extracting watermark from XLSX: {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def embed_watermark_pptx(pptx_path, watermark_data, output_path, encryption_key):
        """Embed watermark in PPTX file as document property"""
        # Import required libraries
        from pptx import Presentation
        
        # Encrypt watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Copy the original file to output path
        import shutil
        shutil.copy2(pptx_path, output_path)
        
        # Open the presentation
        prs = Presentation(output_path)
        
        # Add custom property
        prs.core_properties.category = f"AQUAGUARD_WATERMARK:{encrypted_data}"
        
        # Save the presentation
        prs.save(output_path)
    
    @staticmethod
    def extract_watermark_pptx(pptx_path, encryption_key):
        """Extract watermark from PPTX file document property"""
        try:
            # Import required libraries
            from pptx import Presentation
            
            # Open the presentation
            prs = Presentation(pptx_path)
            
            # Check if watermark exists in category property
            if prs.core_properties.category and prs.core_properties.category.startswith("AQUAGUARD_WATERMARK:"):
                encrypted_data = prs.core_properties.category[len("AQUAGUARD_WATERMARK:"):]
                return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
            
            return None
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error extracting watermark from PPTX: {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate SHA-3 hash of file"""
        sha3 = hashlib.sha3_256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha3.update(chunk)
        return sha3.hexdigest()