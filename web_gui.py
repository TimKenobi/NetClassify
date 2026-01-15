from flask import Flask, render_template, request, jsonify, send_file
import csv
import os
import json
import threading
import time
import tempfile
from datetime import datetime
from werkzeug.utils import secure_filename
import asset_checker

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'output'
ALLOWED_EXTENSIONS = {'csv', 'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Global variables
current_results = []
scan_in_progress = False
scan_progress = 0
scan_status = ""

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page with asset classification interface."""
    return render_template('index.html', results=current_results)

@app.route('/api/results')
def get_results():
    """API endpoint to get results as JSON."""
    return jsonify(current_results)

@app.route('/api/results', methods=['POST'])
def update_results():
    """API endpoint to update results."""
    global current_results
    data = request.get_json()
    if data and 'results' in data:
        current_results = data['results']
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'})

@app.route('/api/scan/status')
def get_scan_status():
    """Get current scan status and progress."""
    return jsonify({
        'in_progress': scan_in_progress,
        'progress': scan_progress,
        'status': scan_status
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new asset classification scan."""
    global scan_in_progress, scan_progress, scan_status, current_results

    if scan_in_progress:
        return jsonify({'status': 'error', 'message': 'Scan already in progress'})

    try:
        # Get form data
        data = request.get_json()
        csv_filename = data.get('csv_file')
        owned_filename = data.get('owned_file', 'OwnedAssets.txt')
        status_filter = data.get('status_filter', 'not_reviewed')
        output_filename = data.get('output_file', f'scan_results_{int(time.time())}.csv')

        if not csv_filename:
            return jsonify({'status': 'error', 'message': 'No CSV file specified'})

        # Build file paths
        csv_path = os.path.join(app.config['UPLOAD_FOLDER'], csv_filename)
        owned_path = owned_filename if os.path.exists(owned_filename) else 'OwnedAssets.txt'
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)

        if not os.path.exists(csv_path):
            return jsonify({'status': 'error', 'message': f'CSV file not found: {csv_filename}'})

        # Start scan in background thread
        scan_in_progress = True
        scan_progress = 0
        scan_status = "Initializing scan..."

        def run_scan():
            global scan_in_progress, scan_progress, scan_status, current_results
            try:
                scan_status = "Loading configuration..."
                scan_progress = 10

                # Run the asset classification
                scan_status = "Processing assets..."
                results = asset_checker.main(owned_path, output_path, csv_path, status_filter)

                scan_status = "Processing results..."
                scan_progress = 90

                # Update global results
                current_results = results

                scan_status = "Scan completed successfully!"
                scan_progress = 100

            except Exception as e:
                scan_status = f"Scan failed: {str(e)}"
                scan_progress = -1
            finally:
                scan_in_progress = False

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

        return jsonify({'status': 'success', 'message': 'Scan started'})

    except Exception as e:
        scan_in_progress = False
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload a file to the server."""
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'})

    if file and allowed_file(file.filename):
        # Clear existing files in uploads folder
        for existing_file in os.listdir(app.config['UPLOAD_FOLDER']):
            existing_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_file)
            if os.path.isfile(existing_path):
                os.unlink(existing_path)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({'status': 'success', 'filename': filename})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid file type'})

@app.route('/api/files')
def list_files():
    """List available files in uploads directory."""
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if allowed_file(filename):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            stat = os.stat(filepath)
            files.append({
                'name': filename,
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    return jsonify(files)

@app.route('/api/download/<filename>')
def download_file(filename):
    """Download a file from the output directory."""
    filepath = os.path.join(app.config['OUTPUT_FOLDER'], secure_filename(filename))
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return jsonify({'status': 'error', 'message': 'File not found'})

@app.route('/load/<filename>')
def load_file(filename):
    """Load results from a CSV file."""
    global current_results
    filepath = os.path.join(app.config['OUTPUT_FOLDER'], filename)
    if os.path.exists(filepath):
        current_results = []
        with open(filepath, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                current_results.append(dict(row))
        return jsonify({'status': 'success', 'count': len(current_results)})
    return jsonify({'status': 'error', 'message': 'File not found'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)