# Secure File Upload Portal using Python Flask and PyCryptodome
# This application provides a web interface to upload files,
# encrypts them using AES-GCM, and allows for their secure download and decryption.

import os
from flask import Flask, request, redirect, url_for, render_template_string, send_from_directory, flash, abort, send_file
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import secrets

# --- Configuration ---
# Directory to store encrypted files.
UPLOAD_FOLDER = 'encrypted_uploads'
# Secret key for Flask session management (used for flashing messages).
# In a real application, this should be a long, random, and secret string.
SECRET_KEY = secrets.token_hex(16)
# **CRITICAL**: AES encryption key. This MUST be 16, 24, or 32 bytes long.
# For this project, we are hardcoding it. In a production environment, this is a
# major security risk. The key should be managed securely using a Hardware
# Security Module (HSM), a cloud KMS, or at least environment variables.
AES_KEY = b'MySuperSecretKey1234567890123456' # Using a 32-byte key for AES-256

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY

# Ensure the upload folder exists.
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- HTML Template ---
# A simple, user-friendly interface using Tailwind CSS for styling.
# The template is embedded here for simplicity.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-gray-100 text-gray-800">
    <div class="container mx-auto p-4 sm:p-6 lg:p-8">
        <div class="max-w-3xl mx-auto bg-white rounded-2xl shadow-lg p-8">
            <h1 class="text-3xl font-bold text-center text-gray-900 mb-2">Secure File Upload Portal</h1>
            <p class="text-center text-gray-500 mb-8">Upload a file to encrypt and store it securely.</p>

            <!-- Flash Messages -->
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, message in messages %}
                  <div class="mb-4 p-4 rounded-lg {{ 'bg-green-100 text-green-800' if category == 'success' else 'bg-red-100 text-red-800' }}" role="alert">
                    {{ message }}
                  </div>
                {% endfor %}
              {% endif %}
            {% endwith %}

            <!-- File Upload Form -->
            <div class="bg-gray-50 border-2 border-dashed border-gray-300 rounded-xl p-8 text-center mb-8">
                <form action="/upload" method="post" enctype="multipart/form-data">
                    <svg class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48" aria-hidden="true">
                        <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                    <p class="mt-2 text-sm text-gray-600">
                        <label for="file-upload" class="relative cursor-pointer bg-white rounded-md font-medium text-indigo-600 hover:text-indigo-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-indigo-500">
                            <span>Select a file</span>
                            <input id="file-upload" name="file" type="file" class="sr-only">
                        </label>
                    </p>
                    <p class="text-xs text-gray-500 mt-1">Any file type. Max 16MB.</p>
                    <button type="submit" class="mt-6 inline-flex items-center px-6 py-3 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                        Upload and Encrypt
                    </button>
                </form>
            </div>

            <!-- File List -->
            <div class="flow-root">
                <h2 class="text-2xl font-semibold text-gray-900 mb-4">Stored Files</h2>
                <ul role="list" class="-my-5 divide-y divide-gray-200">
                    {% if files %}
                        {% for file in files %}
                            <li class="py-4">
                                <div class="flex items-center space-x-4">
                                    <div class="flex-shrink-0">
                                        <svg class="h-8 w-8 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                        </svg>
                                    </div>
                                    <div class="flex-1 min-w-0">
                                        <p class="text-sm font-medium text-gray-900 truncate">{{ file }}</p>
                                        <p class="text-sm text-gray-500 truncate">Encrypted with AES-256 GCM</p>
                                    </div>
                                    <div>
                                        <a href="{{ url_for('download_decrypted_file', filename=file) }}" class="inline-flex items-center shadow-sm px-3 py-2 border border-gray-300 text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                                            Download
                                        </a>
                                    </div>
                                </div>
                            </li>
                        {% endfor %}
                    {% else %}
                        <li class="py-4 text-center text-gray-500">No files have been uploaded yet.</li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
"""

# --- Core Functions ---

def encrypt_file(file_path, data):
    """Encrypts data using AES-GCM and saves it to a file."""
    try:
        # AES-GCM is an authenticated encryption mode. It provides confidentiality
        # and authenticity. The nonce (number used once) must be unique for each
        # encryption with the same key.
        cipher = AES.new(AES_KEY, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # The file is saved in the format: nonce + tag + ciphertext
        # This allows us to retrieve the necessary components for decryption.
        with open(file_path, 'wb') as f:
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)
        return True
    except Exception as e:
        print(f"Encryption failed: {e}")
        return False

def decrypt_file(file_path):
    """Reads an encrypted file and decrypts its content."""
    try:
        with open(file_path, 'rb') as f:
            # Read the components in the same order they were written.
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        # Create the cipher with the same key and the retrieved nonce.
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        # Decrypting and verifying the authenticity tag. If the tag does not match,
        # it means the data has been tampered with, and a ValueError will be raised.
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except (ValueError, KeyError) as e:
        # This error is critical as it indicates a failed integrity check.
        print(f"Decryption failed (integrity check failed): {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None


# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the main page with a list of uploaded files."""
    try:
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        # Filter out any system files like .DS_Store
        files = [f for f in files if not f.startswith('.')]
    except FileNotFoundError:
        files = []
    return render_template_string(HTML_TEMPLATE, files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles the file upload, encrypts it, and saves it."""
    if 'file' not in request.files:
        flash('No file part in the request.', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('index'))

    if file:
        # Sanitize the filename to prevent security issues like directory traversal.
        filename = secure_filename(file.filename)
        # We append .enc to signify it's an encrypted file.
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename + ".enc")
        
        file_data = file.read()
        
        # Encrypt the file data before saving.
        if encrypt_file(encrypted_filepath, file_data):
            flash(f'File "{filename}" has been successfully uploaded and encrypted.', 'success')
        else:
            flash('File encryption failed. Please check server logs.', 'error')
            
        return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/download_decrypted/<filename>')
def download_decrypted_file(filename):
    """This is an improved download route that decrypts in memory."""
    safe_filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

    if not os.path.exists(filepath):
        return abort(404)

    decrypted_data = decrypt_file(filepath)

    if decrypted_data is None:
        flash('Decryption failed! The file may be corrupt or its integrity compromised.', 'error')
        return redirect(url_for('index'))

    from io import BytesIO
    buffer = BytesIO()
    buffer.write(decrypted_data)
    buffer.seek(0)
    
    original_filename = os.path.splitext(safe_filename)[0]

    return send_file(
        buffer,
        as_attachment=True,
        download_name=original_filename,
        mimetype='application/octet-stream'
    )


# --- Main Execution ---
if __name__ == '__main__':
    # Running in debug mode is convenient for development but should be
    # turned off in a production environment.
    app.run(debug=True)
