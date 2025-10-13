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
        # Open image
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Encrypt watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Convert encrypted data to binary
        binary_data = ''.join(format(ord(char), '08b') for char in encrypted_data)
        binary_data += '00000000'  # End marker
        
        # Check if image has enough pixels to store the watermark
        if img.width * img.height < len(binary_data):
            raise ValueError("Image too small to embed the watermark")
        
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
        watermarked_img = Image.fromarray(img_array)
        watermarked_img.save(output_path)
        
    @staticmethod
    def extract_watermark_lsb(image_path, encryption_key):
        """Extract watermark from image using LSB steganography"""
        # Open image
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Extract binary data from LSB
        binary_data = ""
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                for k in range(3):  # RGB channels
                    binary_data += str(img_array[i, j, k] & 1)
                    
                    # Check for end marker (8 zeros)
                    if len(binary_data) >= 8 and binary_data[-8:] == "00000000":
                        # Remove end marker
                        binary_data = binary_data[:-8]
                        
                        # Convert binary to string
                        encrypted_data = ""
                        for idx in range(0, len(binary_data), 8):
                            if idx + 8 <= len(binary_data):
                                byte = binary_data[idx:idx+8]
                                encrypted_data += chr(int(byte, 2))
                        
                        # Decrypt data
                        return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
        
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
        # Open PDF
        pdf_reader = PyPDF2.PdfReader(pdf_path)
        
        # Get metadata
        metadata = pdf_reader.metadata
        
        # Check if watermark exists
        if "/AquaGuardWatermark" in metadata:
            encrypted_data = metadata["/AquaGuardWatermark"]
            return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
        
        return None
    
    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate SHA-3 hash of file"""
        sha3 = hashlib.sha3_256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha3.update(chunk)
        return sha3.hexdigest()