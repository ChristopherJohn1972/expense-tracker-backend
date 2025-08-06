# app.py
from flask import Flask, render_template, request, jsonify
import os
import re
import pytesseract
from PIL import Image
import uuid
import numpy as np
from io import BytesIO

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Import your CRUD module
try:
    from crud import create_receipt
except ImportError:
    # Fallback for demonstration
    def create_receipt(data):
        print(f"Would create receipt: {data}")
        return data

def process_image(image):
    """Process uploaded image and extract receipt data"""
    # Convert to PIL Image
    img = Image.open(BytesIO(image))

    # Preprocess image for better OCR
    img = preprocess_image(np.array(img))

    # Extract text
    text = pytesseract.image_to_string(img)

    # Parse receipt data
    return parse_receipt_text(text)

def preprocess_image(image):
    """Enhance image for better OCR results"""
    # Convert to grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Enhance contrast
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8,8))
    enhanced = clahe.apply(gray)

    # Thresholding
    _, thresh = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    # Noise reduction
    denoised = cv2.medianBlur(thresh, 3)
    return Image.fromarray(denoised)

def parse_receipt_text(text):
    """Parse extracted text into structured data"""
    data = {
        'vendor': 'Unknown',
        'date': None,
        'total': 0.0,
        'items': []
    }

    # Vendor detection
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    if lines:
        data['vendor'] = lines[0]

    # Date detection
    date_patterns = [
        r'\d{2}/\d{2}/\d{4}', r'\d{4}-\d{2}-\d{2}', r'\d{2} \w{3} \d{4}'
    ]
    for pattern in date_patterns:
        match = re.search(pattern, text)
        if match:
            data['date'] = match.group()
            break

    # Total amount detection
    total_patterns = [
        r'total\s*[\$\£\€]?\s*(\d+\.\d{2})',
        r'amount due\s*[\$\£\€]?\s*(\d+\.\d{2})',
        r'balance due\s*[\$\£\€]?\s*(\d+\.\d{2})'
    ]
    for pattern in total_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            try:
                data['total'] = float(match.group(1))
            except ValueError:
                pass
            break

    return data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_receipt():
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400

    image = request.files['image'].read()
    if not image:
        return jsonify({'error': 'Empty image'}), 400

    try:
        # Process receipt
        receipt_data = process_image(image)

        # Save to database
        result = create_receipt(receipt_data)

        # Save image for reference
        filename = f"{uuid.uuid4()}.jpg"
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'wb') as f:
            f.write(image)

        return jsonify({
            'status': 'success',
            'receipt': receipt_data,
            'image': filename
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')  # Add SSL for camera access
