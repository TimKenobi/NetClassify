from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import csv
import os
import json
import threading
import time
import tempfile
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from functools import wraps
import asset_checker

app = Flask(__name__)

# Security: Set a strong secret key for session management
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key-please-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Configuration
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'output'
ALLOWED_EXTENSIONS = {'csv', 'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Global variables with thread safety
current_results = []
scan_in_progress = False
scan_progress = 0
scan_status = ""

# Thread safety locks
results_lock = threading.Lock()
scan_lock = threading.Lock()

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Security: Authentication decorator
def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Security: Input validation helper
def validate_filename(filename):
    """Validate input filename to prevent path traversal"""
    if not filename:
        return False
    # Use secure_filename and ensure it's not empty after sanitization
    safe_name = secure_filename(filename)
    if not safe_name or '..' in filename or '/' in filename or '\\' in filename:
        return False
    return True

def validate_status_filter(status_filter):
    """Validate status filter input"""
    allowed_statuses = ['all', 'approved', 'sas', 'review needed', 'deny', 'not_reviewed']
    for status in status_filter.split(','):
        if status.strip().lower() not in allowed_statuses:
            return False
    return True

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Security: Login routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint with environment variable-based authentication"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else {}
        password = data.get('password', '')
        default_password = os.getenv('NETCLASSIFY_PASSWORD', 'admin')
        
        if password == default_password:
            session.permanent = True
            session['authenticated'] = True
            return jsonify({'status': 'success', 'message': 'Logged in successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    # GET request returns login page or redirect if already authenticated
    if 'authenticated' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint"""
    session.clear()
    return jsonify({'status': 'success', 'message': 'Logged out successfully'})

@app.route('/')
def index():
    """Main page with asset classification interface."""
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    with results_lock:
        results_copy = list(current_results)
    return render_template('index.html', results=results_copy)

@app.route('/api/results')
@login_required
def get_results():
    """API endpoint to get results as JSON."""
    with results_lock:
        results_copy = list(current_results)
    return jsonify(results_copy)

@app.route('/api/results', methods=['POST'])
@login_required
def update_results():
    """API endpoint to update results."""
    global current_results
    data = request.get_json()
    if data and 'results' in data:
        with results_lock:
            current_results = data['results']
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'})

@app.route('/api/scan/status')
@login_required
def get_scan_status():
    """Get current scan status and progress."""
    with scan_lock:
        status_data = {
            'in_progress': scan_in_progress,
            'progress': scan_progress,
            'status': scan_status
        }
    return jsonify(status_data)

@app.route('/api/scan', methods=['POST'])
@login_required
def start_scan():
    """Start a new asset classification scan."""
    global scan_in_progress, scan_progress, scan_status, current_results

    with scan_lock:
        if scan_in_progress:
            return jsonify({'status': 'error', 'message': 'Scan already in progress'})

    try:
        # Get form data
        data = request.get_json()
        csv_filename = data.get('csv_file', '').strip()
        owned_filename = data.get('owned_file', 'OwnedAssets.txt').strip()
        status_filter = data.get('status_filter', 'not_reviewed').strip()
        output_filename = data.get('output_file', f'scan_results_{int(time.time())}.csv').strip()

        # Input validation
        if not csv_filename:
            return jsonify({'status': 'error', 'message': 'No CSV file specified'})
        
        if not validate_filename(csv_filename):
            return jsonify({'status': 'error', 'message': 'Invalid CSV filename'})
        
        if not validate_status_filter(status_filter):
            return jsonify({'status': 'error', 'message': 'Invalid status filter'})
        
        if not validate_filename(output_filename):
            return jsonify({'status': 'error', 'message': 'Invalid output filename'})

        # Build file paths
        csv_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(csv_filename))
        owned_path = owned_filename if os.path.exists(owned_filename) else 'OwnedAssets.txt'
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], secure_filename(output_filename))

        if not os.path.exists(csv_path):
            return jsonify({'status': 'error', 'message': 'CSV file not found'})

        # Start scan in background thread with lock
        with scan_lock:
            scan_in_progress = True
            scan_progress = 0
            scan_status = "Initializing scan..."

        def run_scan():
            global scan_in_progress, scan_progress, scan_status, current_results
            try:
                with scan_lock:
                    scan_status = "Loading configuration..."
                    scan_progress = 10

                # Run the asset classification
                with scan_lock:
                    scan_status = "Processing assets..."
                results = asset_checker.main(owned_path, output_path, csv_path, status_filter)

                with scan_lock:
                    scan_status = "Processing results..."
                    scan_progress = 90

                # Update global results with lock
                with results_lock:
                    current_results = results

                with scan_lock:
                    scan_status = "Scan completed successfully!"
                    scan_progress = 100

            except Exception as e:
                import logging
                logging.error(f"Scan error: {str(e)}")
                with scan_lock:
                    # Sanitize error message - don't expose internal details
                    scan_status = "Scan failed: An error occurred during processing"
                    scan_progress = -1
            finally:
                with scan_lock:
                    scan_in_progress = False

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

        return jsonify({'status': 'success', 'message': 'Scan started'})

    except Exception as e:
        import logging
        logging.error(f"Scan request error: {str(e)}")
        with scan_lock:
            scan_in_progress = False
        # Sanitize error message
        return jsonify({'status': 'error', 'message': 'Failed to start scan'})

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    """Upload a file to the server."""
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400

        if file and allowed_file(file.filename):
            # Validate file size (additional check)
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to start
            
            max_size = 16 * 1024 * 1024  # 16MB
            if file_size > max_size:
                return jsonify({'status': 'error', 'message': 'File too large'}), 413
            
            # Clear existing files in uploads folder
            for existing_file in os.listdir(app.config['UPLOAD_FOLDER']):
                existing_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_file)
                if os.path.isfile(existing_path):
                    try:
                        os.unlink(existing_path)
                    except OSError:
                        pass
            
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return jsonify({'status': 'success', 'filename': filename})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid file type'}), 400
    except Exception as e:
        import logging
        logging.error(f"Upload error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Upload failed'}), 500

@app.route('/api/files')
@login_required
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
@login_required
def download_file(filename):
    """Download a file from the output directory."""
    try:
        # Validate filename
        if not validate_filename(filename):
            return jsonify({'status': 'error', 'message': 'Invalid filename'}), 400
        
        filepath = os.path.join(app.config['OUTPUT_FOLDER'], secure_filename(filename))
        if os.path.exists(filepath) and os.path.isfile(filepath):
            return send_file(filepath, as_attachment=True)
        return jsonify({'status': 'error', 'message': 'File not found'}), 404
    except Exception as e:
        import logging
        logging.error(f"Download error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Download failed'}), 500
@app.route('/load/<filename>')
@login_required
def load_file(filename):
    """Load results from a CSV file."""
    global current_results
    try:
        # Validate filename
        if not validate_filename(filename):
            return jsonify({'status': 'error', 'message': 'Invalid filename'}), 400
        
        filepath = os.path.join(app.config['OUTPUT_FOLDER'], secure_filename(filename))
        if os.path.exists(filepath) and os.path.isfile(filepath):
            results = []
            with open(filepath, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    results.append(dict(row))
            with results_lock:
                current_results = results
            return jsonify({'status': 'success', 'count': len(results)})
        return jsonify({'status': 'error', 'message': 'File not found'}), 404
    except Exception as e:
        import logging
        logging.error(f"Load file error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Load failed'}), 500

if __name__ == '__main__':
    import os
    flask_env = os.getenv('FLASK_ENV', 'production')
    debug_mode = flask_env != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=5001)