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
import wave
import struct
# import moviepy.editor as mp - removed to fix dependency issues
import tempfile
import zipfile
import shutil
import re

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
        
        # Convert data to JSON string and then to bytes
        data_bytes = json.dumps(data).encode('utf-8')
        
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)
        
        # Create cipher object and encrypt
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
        
        # Combine IV and ciphertext and encode as base64
        result = base64.b64encode(iv + ct_bytes).decode('utf-8')
        return result
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Decrypt data using AES-256"""
        # Add timeout to prevent infinite processing
        import signal, platform
        
        class TimeoutException(Exception):
            pass
            
        def timeout_handler(signum, frame):
            raise TimeoutException("Decryption timed out")
            
        try:
            # Set timeout only on Unix systems (not on Windows)
            if platform.system() != 'Windows':
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(3)  # 3-second timeout
            # Convert key from hex to bytes
            key_bytes = bytes.fromhex(key)
            
            # Decode the base64 string
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Extract IV (first 16 bytes) and ciphertext
            iv = encrypted_bytes[:16]
            ct = encrypted_bytes[16:]
            
            # Create cipher object and decrypt
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            
            # Convert bytes to JSON object
            result = json.loads(pt.decode('utf-8'))
            # Reset the alarm if on Unix
            if platform.system() != 'Windows':
                signal.alarm(0)
            return result
        except TimeoutException:
            print("Decryption timed out")
            return None
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            # Reset the alarm in case of other exceptions
            if platform.system() != 'Windows':
                signal.alarm(0)
            return None
    
    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate SHA-3 hash of a file"""
        h = hashlib.sha3_256()
        with open(file_path, 'rb') as file:
            # Read file in chunks to handle large files
            chunk = 0
            while chunk := file.read(8192):
                h.update(chunk)
        return h.hexdigest()
    
    @staticmethod
    def embed_watermark_lsb(input_image_path, watermark_data, output_image_path, encryption_key):
        """Embed watermark in image using LSB steganography"""
        # Encrypt the watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Convert encrypted data to binary
        binary_data = ''.join(format(ord(char), '08b') for char in encrypted_data)
        binary_data += '00000000'  # Add terminator
        
        # Open the image
        img = Image.open(input_image_path)
        width, height = img.size
        
        # Convert image to RGB if it's not
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Get pixel data
        pixels = list(img.getdata())
        
        # Check if the image can hold the watermark
        if len(binary_data) > len(pixels) * 3:
            raise ValueError("Image too small to embed the watermark")
        
        # Embed the watermark
        data_index = 0
        modified_pixels = []
        
        for i, pixel in enumerate(pixels):
            r, g, b = pixel
            
            # Modify the least significant bit of each color channel
            if data_index < len(binary_data):
                r = (r & ~1) | int(binary_data[data_index])
                data_index += 1
            
            if data_index < len(binary_data):
                g = (g & ~1) | int(binary_data[data_index])
                data_index += 1
            
            if data_index < len(binary_data):
                b = (b & ~1) | int(binary_data[data_index])
                data_index += 1
            
            modified_pixels.append((r, g, b))
            
            if data_index >= len(binary_data):
                # Add remaining pixels unchanged
                modified_pixels.extend(pixels[i+1:])
                break
        
        # Create a new image with the modified pixels
        modified_img = Image.new('RGB', (width, height))
        modified_img.putdata(modified_pixels)
        
        # Save the watermarked image
        modified_img.save(output_image_path)
    
    @staticmethod
    def extract_watermark_lsb(image_path, encryption_key):
        """Extract watermark from image using LSB steganography"""
        # Open the image
        img = Image.open(image_path)
        
        # Convert image to RGB if it's not
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Get pixel data
        pixels = list(img.getdata())
        
        # Extract the binary data
        binary_data = ""
        for pixel in pixels:
            r, g, b = pixel
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
            
            # Check for terminator
            if len(binary_data) >= 8 and binary_data[-8:] == '00000000':
                binary_data = binary_data[:-8]  # Remove terminator
                break
        
        # Convert binary to string
        chars = []
        for i in range(0, len(binary_data), 8):
            if i + 8 <= len(binary_data):
                byte = binary_data[i:i+8]
                chars.append(chr(int(byte, 2)))
        
        encrypted_data = ''.join(chars)
        
        # Decrypt the data
        return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
    
    @staticmethod
    def embed_watermark_pdf(input_pdf_path, watermark_data, output_pdf_path, encryption_key):
        """Embed watermark in PDF file"""
        # Encrypt the watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Read the original PDF
        reader = PyPDF2.PdfReader(input_pdf_path)
        writer = PyPDF2.PdfWriter()
        
        # Copy all pages from the original PDF
        for page_num in range(len(reader.pages)):
            writer.add_page(reader.pages[page_num])
        
        # Create a metadata dictionary with our watermark
        metadata = {
            "watermark": encrypted_data
        }
        
        # Add metadata to the PDF
        writer.add_metadata(metadata)
        
        # Save the watermarked PDF
        with open(output_pdf_path, 'wb') as output_file:
            writer.write(output_file)
    
    @staticmethod
    def extract_watermark_pdf(pdf_path, encryption_key):
        """Extract watermark from PDF file"""
        try:
            # Open the PDF file
            reader = PyPDF2.PdfReader(pdf_path)
            
            # Get the document info dictionary
            metadata = reader.metadata
            
            # Extract the watermark if it exists
            if metadata and "/watermark" in metadata:
                encrypted_data = metadata["/watermark"]
                return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
            
            return None
        except Exception as e:
            print(f"Error extracting watermark from PDF: {str(e)}")
            return None
    
    @staticmethod
    def embed_watermark_audio(input_audio_path, watermark_data, output_audio_path, encryption_key):
        """Embed watermark in audio file using LSB steganography"""
        # Encrypt the watermark data
        encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
        
        # Convert encrypted data to binary
        binary_data = ''.join(format(ord(char), '08b') for char in encrypted_data)
        binary_data += '00000000'  # Add terminator
        
        # Open the audio file
        with wave.open(input_audio_path, 'rb') as audio_file:
            # Get audio parameters
            n_channels = audio_file.getnchannels()
            sample_width = audio_file.getsampwidth()
            framerate = audio_file.getframerate()
            n_frames = audio_file.getnframes()
            
            # Read all frames
            frames = audio_file.readframes(n_frames)
        
        # Convert frames to samples
        if sample_width == 1:  # 8-bit samples
            fmt = f"{n_frames}B"
            samples = list(struct.unpack(fmt, frames))
            max_val = 255
        elif sample_width == 2:  # 16-bit samples
            fmt = f"{n_frames}h"
            samples = list(struct.unpack(fmt, frames))
            max_val = 32767
        else:
            raise ValueError("Unsupported sample width")
        
        # Check if the audio can hold the watermark
        if len(binary_data) > len(samples):
            raise ValueError("Audio too small to embed the watermark")
        
        # Embed the watermark
        data_index = 0
        for i in range(len(samples)):
            if data_index < len(binary_data):
                # Modify the least significant bit
                samples[i] = (samples[i] & ~1) | int(binary_data[data_index])
                data_index += 1
            
            if data_index >= len(binary_data):
                break
        
        # Convert samples back to frames
        if sample_width == 1:
            modified_frames = struct.pack(fmt, *samples)
        else:
            modified_frames = struct.pack(fmt, *samples)
        
        # Create a new audio file with the modified frames
        with wave.open(output_audio_path, 'wb') as output_file:
            output_file.setparams((n_channels, sample_width, framerate, n_frames, 'NONE', 'not compressed'))
            output_file.writeframes(modified_frames)
    
    @staticmethod
    def extract_watermark_audio(audio_path, encryption_key):
        """Extract watermark from audio file"""
        try:
            # Open the audio file
            with wave.open(audio_path, 'rb') as audio_file:
                # Get audio parameters
                n_channels = audio_file.getnchannels()
                sample_width = audio_file.getsampwidth()
                n_frames = audio_file.getnframes()
                
                # Read all frames
                frames = audio_file.readframes(n_frames)
            
            # Convert frames to samples
            if sample_width == 1:  # 8-bit samples
                fmt = f"{n_frames}B"
                samples = list(struct.unpack(fmt, frames))
            elif sample_width == 2:  # 16-bit samples
                fmt = f"{n_frames}h"
                samples = list(struct.unpack(fmt, frames))
            else:
                raise ValueError("Unsupported sample width")
            
            # Extract the binary data
            binary_data = ""
            for sample in samples:
                binary_data += str(sample & 1)
                
                # Check for terminator
                if len(binary_data) >= 8 and binary_data[-8:] == '00000000':
                    binary_data = binary_data[:-8]  # Remove terminator
                    break
            
            # Convert binary to string
            chars = []
            for i in range(0, len(binary_data), 8):
                if i + 8 <= len(binary_data):
                    byte = binary_data[i:i+8]
                    chars.append(chr(int(byte, 2)))
            
            encrypted_data = ''.join(chars)
            
            # Decrypt the data
            return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
        except Exception as e:
            print(f"Error extracting watermark from audio: {str(e)}")
            return None
    
    @staticmethod
    def embed_watermark_video(input_video_path, watermark_data, output_video_path, encryption_key):
        """Embed watermark in video file by watermarking its audio track"""
        try:
            # Create a temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract audio from video
                video = mp.VideoFileClip(input_video_path)
                audio_path = os.path.join(temp_dir, "audio.wav")
                video.audio.write_audiofile(audio_path, codec='pcm_s16le')
                
                # Watermark the audio
                watermarked_audio_path = os.path.join(temp_dir, "watermarked_audio.wav")
                WatermarkGenerator.embed_watermark_audio(audio_path, watermark_data, watermarked_audio_path, encryption_key)
                
                # Create a new video with the watermarked audio
                watermarked_audio = mp.AudioFileClip(watermarked_audio_path)
                video_with_watermarked_audio = video.set_audio(watermarked_audio)
                
                # Write the final video
                video_with_watermarked_audio.write_videofile(output_video_path, codec='libx264', audio_codec='aac')
                
                # Close clips to release resources
                video.close()
                watermarked_audio.close()
                video_with_watermarked_audio.close()
                
        except Exception as e:
            print(f"Error embedding watermark in video: {str(e)}")
            raise
    
    @staticmethod
    def extract_watermark_video(video_path, encryption_key):
        """Extract watermark from video file by extracting from its audio track"""
        try:
            # Create a temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract audio from video
                video = mp.VideoFileClip(video_path)
                audio_path = os.path.join(temp_dir, "audio.wav")
                video.audio.write_audiofile(audio_path, codec='pcm_s16le')
                
                # Extract watermark from audio
                watermark_data = WatermarkGenerator.extract_watermark_audio(audio_path, encryption_key)
                
                # Close clip to release resources
                video.close()
                
                return watermark_data
                
        except Exception as e:
            print(f"Error extracting watermark from video: {str(e)}")
            return None
    
    @staticmethod
    def embed_watermark_docx(input_path, watermark_data, output_path, encryption_key):
        """Embed watermark in Word document (.docx) file"""
        try:
            # Encrypt the watermark data
            encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
            
            # Create a temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy the original file to the temp directory
                temp_docx = os.path.join(temp_dir, "temp.docx")
                shutil.copy2(input_path, temp_docx)
                
                # Word documents are ZIP files, extract it
                extract_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                
                with zipfile.ZipFile(temp_docx, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
                # Create a custom XML part to store our watermark
                custom_dir = os.path.join(extract_dir, "customXml")
                os.makedirs(custom_dir, exist_ok=True)
                
                # Create watermark XML file
                watermark_xml = os.path.join(custom_dir, "watermark.xml")
                with open(watermark_xml, 'w') as f:
                    f.write(f'<watermark>{encrypted_data}</watermark>')
                
                # Create content types references if needed
                types_path = os.path.join(extract_dir, "[Content_Types].xml")
                if os.path.exists(types_path):
                    with open(types_path, 'r') as f:
                        content = f.read()
                    
                    # Add custom XML content type if not present
                    if "<Default Extension=\"xml\"" not in content:
                        content = content.replace("</Types>", 
                                                "<Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>")
                        with open(types_path, 'w') as f:
                            f.write(content)
                
                # Repackage the document
                with zipfile.ZipFile(output_path, 'w') as docx_zip:
                    for folder_name, subfolders, filenames in os.walk(extract_dir):
                        for filename in filenames:
                            file_path = os.path.join(folder_name, filename)
                            arcname = os.path.relpath(file_path, extract_dir)
                            docx_zip.write(file_path, arcname)
                            
        except Exception as e:
            print(f"Error embedding watermark in Word document: {str(e)}")
            raise
    
    @staticmethod
    def extract_watermark_docx(docx_path, encryption_key):
        """Extract watermark from Word document (.docx) file"""
        try:
            # Create a temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract the docx (it's a ZIP file)
                with zipfile.ZipFile(docx_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Look for our custom XML watermark
                watermark_path = os.path.join(temp_dir, "customXml", "watermark.xml")
                
                if not os.path.exists(watermark_path):
                    # Try alternative locations
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            if file == "watermark.xml":
                                watermark_path = os.path.join(root, file)
                                break
                
                if not os.path.exists(watermark_path):
                    print("No watermark.xml found in DOCX file")
                    return None
                
                # Read the watermark data
                with open(watermark_path, 'r') as f:
                    content = f.read()
                
                # Extract the encrypted data
                match = re.search(r'<watermark>(.*?)</watermark>', content)
                if not match:
                    print("No watermark tag found in XML")
                    return None
                
                encrypted_data = match.group(1)
                
                # Decrypt the data
                return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
                
        except Exception as e:
            print(f"Error extracting watermark from Word document: {str(e)}")
            return None
    
    @staticmethod
    def embed_watermark_xlsx(input_path, watermark_data, output_path, encryption_key):
        """Embed watermark in Excel spreadsheet (.xlsx) file"""
        try:
            # Encrypt the watermark data
            encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
            
            # Create a temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy the original file to the temp directory
                temp_xlsx = os.path.join(temp_dir, "temp.xlsx")
                shutil.copy2(input_path, temp_xlsx)
                
                # Excel files are ZIP files, extract it
                extract_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                
                with zipfile.ZipFile(temp_xlsx, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
                # Create a custom XML part to store our watermark
                custom_dir = os.path.join(extract_dir, "customXml")
                os.makedirs(custom_dir, exist_ok=True)
                
                # Create watermark XML file
                watermark_xml = os.path.join(custom_dir, "watermark.xml")
                with open(watermark_xml, 'w') as f:
                    f.write(f'<watermark>{encrypted_data}</watermark>')
                
                # Create content types references if needed
                types_path = os.path.join(extract_dir, "[Content_Types].xml")
                if os.path.exists(types_path):
                    with open(types_path, 'r') as f:
                        content = f.read()
                    
                    # Add custom XML content type if not present
                    if "<Default Extension=\"xml\"" not in content:
                        content = content.replace("</Types>", 
                                                "<Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>")
                        with open(types_path, 'w') as f:
                            f.write(content)
                
                # Repackage the document
                with zipfile.ZipFile(output_path, 'w') as xlsx_zip:
                    for folder_name, subfolders, filenames in os.walk(extract_dir):
                        for filename in filenames:
                            file_path = os.path.join(folder_name, filename)
                            arcname = os.path.relpath(file_path, extract_dir)
                            xlsx_zip.write(file_path, arcname)
                            
        except Exception as e:
            print(f"Error embedding watermark in Excel spreadsheet: {str(e)}")
            raise
    
    @staticmethod
    def extract_watermark_xlsx(xlsx_path, encryption_key):
        """Extract watermark from Excel spreadsheet (.xlsx) file"""
        try:
            # Create a temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract the xlsx (it's a ZIP file)
                with zipfile.ZipFile(xlsx_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Look for our custom XML watermark
                watermark_path = os.path.join(temp_dir, "customXml", "watermark.xml")
                
                if not os.path.exists(watermark_path):
                    # Try alternative locations
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            if file == "watermark.xml":
                                watermark_path = os.path.join(root, file)
                                break
                
                if not os.path.exists(watermark_path):
                    print("No watermark.xml found in XLSX file")
                    return None
                
                # Read the watermark data
                with open(watermark_path, 'r') as f:
                    content = f.read()
                
                # Extract the encrypted data
                match = re.search(r'<watermark>(.*?)</watermark>', content)
                if not match:
                    print("No watermark tag found in XML")
                    return None
                
                encrypted_data = match.group(1)
                
                # Decrypt the data
                return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
                
        except Exception as e:
            print(f"Error extracting watermark from Excel spreadsheet: {str(e)}")
            return None
    
    @staticmethod
    def embed_watermark_pptx(input_path, watermark_data, output_path, encryption_key):
        """Embed watermark in PowerPoint presentation (.pptx) file"""
        try:
            # Encrypt the watermark data
            encrypted_data = WatermarkGenerator.encrypt_data(watermark_data, encryption_key)
            
            # Create a temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy the original file to the temp directory
                temp_pptx = os.path.join(temp_dir, "temp.pptx")
                shutil.copy2(input_path, temp_pptx)
                
                # PowerPoint files are ZIP files, extract it
                extract_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                
                with zipfile.ZipFile(temp_pptx, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
                # Create a custom XML part to store our watermark
                custom_dir = os.path.join(extract_dir, "customXml")
                os.makedirs(custom_dir, exist_ok=True)
                
                # Create watermark XML file
                watermark_xml = os.path.join(custom_dir, "watermark.xml")
                with open(watermark_xml, 'w') as f:
                    f.write(f'<watermark>{encrypted_data}</watermark>')
                
                # Create content types references if needed
                types_path = os.path.join(extract_dir, "[Content_Types].xml")
                if os.path.exists(types_path):
                    with open(types_path, 'r') as f:
                        content = f.read()
                    
                    # Add custom XML content type if not present
                    if "<Default Extension=\"xml\"" not in content:
                        content = content.replace("</Types>", 
                                                "<Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>")
                        with open(types_path, 'w') as f:
                            f.write(content)
                
                # Repackage the document
                with zipfile.ZipFile(output_path, 'w') as pptx_zip:
                    for folder_name, subfolders, filenames in os.walk(extract_dir):
                        for filename in filenames:
                            file_path = os.path.join(folder_name, filename)
                            arcname = os.path.relpath(file_path, extract_dir)
                            pptx_zip.write(file_path, arcname)
                            
        except Exception as e:
            print(f"Error embedding watermark in PowerPoint presentation: {str(e)}")
            raise
    
    @staticmethod
    def extract_watermark_pptx(pptx_path, encryption_key):
        """Extract watermark from PowerPoint presentation (.pptx) file"""
        try:
            # Create a temporary directory for processing
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract the pptx (it's a ZIP file)
                with zipfile.ZipFile(pptx_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Look for our custom XML watermark
                watermark_path = os.path.join(temp_dir, "customXml", "watermark.xml")
                
                if not os.path.exists(watermark_path):
                    # Try alternative locations
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            if file == "watermark.xml":
                                watermark_path = os.path.join(root, file)
                                break
                
                if not os.path.exists(watermark_path):
                    print("No watermark.xml found in PPTX file")
                    return None
                
                # Read the watermark data
                with open(watermark_path, 'r') as f:
                    content = f.read()
                
                # Extract the encrypted data
                match = re.search(r'<watermark>(.*?)</watermark>', content)
                if not match:
                    print("No watermark tag found in XML")
                    return None
                
                encrypted_data = match.group(1)
                
                # Decrypt the data
                return WatermarkGenerator.decrypt_data(encrypted_data, encryption_key)
                
        except Exception as e:
            print(f"Error extracting watermark from PowerPoint presentation: {str(e)}")
            return None