"""
Module 6: Web Dashboard
Provides visual interface for analyzing sandbox results and exploring network traffic
"""

import os
import sys
import json
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
import logging

# Flask imports
from flask import Flask, render_template, jsonify, request, send_file, Response, current_app
from flask_socketio import SocketIO, emit
from functools import wraps

# Add parent directory to path for module imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Initialize Flask app FIRST
app = Flask(__name__, 
            template_folder='modules/dashboard/templates',
            static_folder='modules/dashboard/static')
app.config['SECRET_KEY'] = 'pdr-dashboard-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Register blueprints - AFTER app is created, BEFORE routes
try:
    from modules.dashboard.api import api_bp
    app.register_blueprint(api_bp)
    print("[OK] API v2 blueprint registered")
except ImportError as e:
    print(f"⚠️  Could not load API v2 blueprint: {e}")

try:
    from modules.sandbox_manager import SandboxManager
    from modules.packet_capture import PacketCapture
    from modules.protocol_analyzer import ProtocolAnalyzer
    from modules.exfiltration_detector import ExfiltrationDetector
    from modules.signature_generator import SignatureGenerator
    MODULES_AVAILABLE = True
except (ImportError, KeyboardInterrupt, Exception) as e:
    MODULES_AVAILABLE = False
    print(f"⚠️  Some modules not available: {e}")

# Global variables
active_analyses = {}
capture_threads = {}
analysis_results = {}
API_KEY = os.environ.get('PDR_API_KEY', 'change-this-in-production')

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if key and key == API_KEY:
            return f(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return decorated

class DashboardManager:
    """
    Manages dashboard state and interactions with other modules
    """
    
    def __init__(self):
        """Initialize dashboard manager"""
        self.dashboard_id = f"dash_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.logger = self._setup_logging()
        
        # Create necessary directories
        os.makedirs('uploads', exist_ok=True)
        os.makedirs('output/analysis', exist_ok=True)
        os.makedirs('output/captures', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
        
        self.logger.info(f"[DASH] DashboardManager initialized: {self.dashboard_id}")
    
    def _setup_logging(self):
        """Setup logging for dashboard"""
        logger = logging.getLogger('Dashboard')
        logger.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler
        try:
            fh = logging.FileHandler('logs/dashboard.log', encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except:
            pass
        
        return logger
    
    def get_system_status(self):
        """Get current system status"""
        return {
            "status": "running",
            "timestamp": datetime.now().isoformat(),
            "modules": {
                "sandbox": MODULES_AVAILABLE,
                "packet_capture": MODULES_AVAILABLE,
                "protocol_analyzer": MODULES_AVAILABLE,
                "exfiltration_detector": MODULES_AVAILABLE,
                "signature_generator": MODULES_AVAILABLE
            },
            "active_analyses": len(active_analyses),
            "storage": {
                "uploads": self._get_dir_size('uploads'),
                "output": self._get_dir_size('output'),
                "reports": self._get_dir_size('reports')
            }
        }
    
    def _get_dir_size(self, path):
        """Get directory size in MB"""
        total = 0
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for f in files:
                    fp = os.path.join(root, f)
                    total += os.path.getsize(fp)
        return round(total / (1024 * 1024), 2)
    
    def get_recent_analyses(self, limit=10):
        """Get list of recent analyses"""
        analyses = []
        output_dir = Path('output/analysis')
        
        if output_dir.exists():
            for file in sorted(output_dir.glob('*.json'), key=os.path.getmtime, reverse=True)[:limit]:
                try:
                    with open(file, 'r') as f:
                        data = json.load(f)
                        analyses.append({
                            "id": data.get('analysis_id', file.stem),
                            "file": file.name,
                            "timestamp": datetime.fromtimestamp(os.path.getmtime(file)).isoformat(),
                            "alerts": len(data.get('alerts', [])),
                            "packets": data.get('statistics', {}).get('total_packets', 0)
                        })
                except:
                    pass
        
        return analyses
    
    def get_recent_reports(self, limit=10):
        """Get list of recent reports"""
        reports = []
        reports_dir = Path('reports')
        
        if reports_dir.exists():
            for file in sorted(reports_dir.glob('*'), key=os.path.getmtime, reverse=True)[:limit]:
                reports.append({
                    "name": file.name,
                    "path": str(file),
                    "size": round(file.stat().st_size / 1024, 2),
                    "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()
                })
        
        return reports
    
    def get_recent_signatures(self, limit=10):
        """Get list of recent signatures"""
        signatures = []
        sig_dir = Path('signatures/custom')
        
        if sig_dir.exists():
            for file in sorted(sig_dir.glob('*.json'), key=os.path.getmtime, reverse=True)[:limit]:
                try:
                    with open(file, 'r') as f:
                        data = json.load(f)
                        signatures.append({
                            "id": data.get('signature_id', file.stem),
                            "file": file.name,
                            "timestamp": data.get('generated', ''),
                            "rules": data.get('rules', {})
                        })
                except:
                    pass
        
        return signatures


# Initialize dashboard manager
dashboard_manager = DashboardManager()


# ============================================================================
# Routes
# ============================================================================

@app.route('/')
def index():
    """Dashboard homepage"""
    return render_template('index.html',
                         system_status=dashboard_manager.get_system_status(),
                         recent_analyses=dashboard_manager.get_recent_analyses(),
                         recent_reports=dashboard_manager.get_recent_reports(),
                         recent_signatures=dashboard_manager.get_recent_signatures())


@app.route('/analysis/<analysis_id>')
def analysis_view(analysis_id):
    """Analysis details view"""
    return render_template('analysis.html', analysis_id=analysis_id)


@app.route('/packets')
def packets_view():
    """Packet explorer view"""
    return render_template('packets.html')


@app.route('/alerts')
def alerts_view():
    """Alerts management view"""
    return render_template('alerts.html')


@app.route('/signatures')
def signatures_view():
    """Signatures view"""
    return render_template('signatures.html')


@app.route('/reports')
def reports_view():
    """Reports view"""
    return render_template('reports.html')


# ============================================================================
# API Endpoints
# ============================================================================

@app.route('/api/v1/status', methods=['GET'])
def api_status():
    """Get system status"""
    return jsonify(dashboard_manager.get_system_status())


@app.route('/api/v1/analyses', methods=['GET'])
def api_list_analyses():
    """List all analyses"""
    limit = request.args.get('limit', 50, type=int)
    analyses = []
    
    output_dir = Path('output/analysis')
    if output_dir.exists():
        for file in sorted(output_dir.glob('*.json'), key=os.path.getmtime, reverse=True)[:limit]:
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    analyses.append({
                        "id": data.get('analysis_id', file.stem),
                        "file": file.name,
                        "timestamp": data.get('timestamp', ''),
                        "alerts": len(data.get('alerts', [])),
                        "protocols": len(data.get('protocols', {})),
                        "flows": data.get('flow_count', 0),
                        "packets": data.get('statistics', {}).get('total_packets', 0)
                    })
            except:
                pass
    
    return jsonify(analyses)


@app.route('/api/v1/analysis/<analysis_id>', methods=['GET'])
def api_get_analysis(analysis_id):
    """Get specific analysis results"""
    # Try different possible filenames
    possible_paths = [
        Path(f'output/analysis/analysis_{analysis_id}.json'),
        Path(f'output/analysis/{analysis_id}.json'),
        Path(f'output/analysis/{analysis_id}')
    ]
    
    for path in possible_paths:
        if path.exists():
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                return jsonify(data)
            except:
                pass
    
    return jsonify({"error": "Analysis not found"}), 404


@app.route('/api/v1/analysis/<analysis_id>/packets', methods=['GET'])
def api_get_analysis_packets(analysis_id):
    """Get packets from analysis"""
    # Look for associated PCAP
    pcap_paths = [
        Path(f'output/captures/capture_{analysis_id}.pcap'),
        Path(f'output/captures/{analysis_id}.pcap'),
        Path(f'output/captures/{analysis_id.replace("analysis", "capture")}.pcap')
    ]
    
    for path in pcap_paths:
        if path.exists():
            return send_file(path, as_attachment=False)
    
    return jsonify({"error": "PCAP file not found"}), 404


@app.route('/api/v1/alerts', methods=['GET'])
def api_get_alerts():
    """Get all alerts from analyses"""
    severity = request.args.get('severity', None)
    limit = request.args.get('limit', 100, type=int)
    
    all_alerts = []
    output_dir = Path('output/analysis')
    
    if output_dir.exists():
        for file in sorted(output_dir.glob('*.json'), key=os.path.getmtime, reverse=True):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    for alert in data.get('alerts', []):
                        alert['analysis_id'] = data.get('analysis_id', file.stem)
                        alert['analysis_time'] = data.get('timestamp', '')
                        
                        if severity and alert.get('severity') != severity:
                            continue
                            
                        all_alerts.append(alert)
                        
                        if len(all_alerts) >= limit:
                            break
            except:
                pass
    
    return jsonify(all_alerts)


@app.route('/api/v1/signatures', methods=['GET'])
def api_get_signatures():
    format_type = request.args.get('format', None)
    limit = request.args.get('limit', 50, type=int)
    
    signatures = []
    sig_dirs = {
        'snort': Path('signatures/snort'),
        'suricata': Path('signatures/suricata'),
        'yara': Path('signatures/yara'),
        'sigma': Path('signatures/sigma'),
        'custom': Path('signatures/custom')
    }
    
    for fmt, path in sig_dirs.items():
        if format_type and fmt != format_type:
            continue
        if path.exists():
            for file in sorted(path.glob('*'), key=os.path.getmtime, reverse=True)[:limit]:
                signatures.append({
                    "format": fmt,
                    "name": file.name,
                    "path": file.as_posix(),  # ← always forward slashes
                    "size": round(file.stat().st_size / 1024, 2),
                    "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()
                })
    
    return jsonify(signatures)


@app.route('/api/v1/reports', methods=['GET'])
def api_get_reports():
    """Get generated reports"""
    format_type = request.args.get('format', None)
    limit = request.args.get('limit', 50, type=int)
    
    reports = []
    reports_dir = Path('reports')
    
    if reports_dir.exists():
        for file in sorted(reports_dir.glob('*'), key=os.path.getmtime, reverse=True)[:limit]:
            fmt = file.suffix[1:] if file.suffix else 'unknown'
            
            if format_type and fmt != format_type:
                continue
                
            reports.append({
                "format": fmt,
                "name": file.name,
                "path": file.as_posix(),
                "size": round(file.stat().st_size / 1024, 2),
                "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat()
            })
    
    return jsonify(reports)


@app.route('/api/v1/analyze/file', methods=['POST'])
@require_api_key
def api_analyze_file():
    """Submit new file for analysis"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Save uploaded file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{file.filename}"
    filepath = os.path.join('uploads', filename)
    file.save(filepath)
    
    # Start analysis in background
    analysis_id = f"analysis_{timestamp}"
    custom_args = request.form.getlist('args') if request.form else []
    
    def run_analysis(args_list):
        """Background analysis task"""
        try:
            packets = []  # Will be filled by capture
            
            # Modules 1 & 2: Run app while capturing
            with SandboxManager() as sandbox:
                with PacketCapture() as capture:
                    # Start capture FIRST
                    capture.start_capture(timeout=30)
                    
                    # THEN run the application
                    sandbox.run_application(filepath, args_list)
                    
                    # Let it run for 30 seconds
                    time.sleep(30)
                    
                    # Stop capture and get packets
                    capture.stop_capture_now()
                    packets = capture.get_packets()
            
            # Modules 3, 4, 5: Analyze captured traffic
            if packets:
                # Module 3: Protocol Analysis
                with ProtocolAnalyzer() as analyzer:
                    analyzer.load_packets(packets)
                    protocol_results = analyzer.analyze()
                    analyzer.generate_report()
                
                # Module 4: Exfiltration Detection
                with ExfiltrationDetector() as detector:
                    detector.load_packets(packets)
                    exfil_results = detector.detect_exfiltration()
                    detector.generate_report()
                
                # Module 5: Signature Generation
                with SignatureGenerator() as generator:
                    generator.load_analysis_results(protocol_results, exfil_results, packets)
                    generator.generate_signatures()
                    generator.generate_report()
                
                # Save combined results
                combined = {
                    "analysis_id": analysis_id,
                    "timestamp": datetime.now().isoformat(),
                    "file": file.filename,
                    "protocol_analysis": protocol_results,
                    "exfiltration_detection": exfil_results,
                    "packet_count": len(packets)
                }
            else:
                # No packets captured
                combined = {
                    "analysis_id": analysis_id,
                    "timestamp": datetime.now().isoformat(),
                    "file": file.filename,
                    "error": "No packets captured",
                    "packet_count": 0
                }
            
            # Save results
            with open(f"output/analysis/{analysis_id}.json", 'w') as f:
                json.dump(combined, f, indent=2, default=str)
            
            # Notify via WebSocket
            socketio.emit('analysis_complete', {
                'analysis_id': analysis_id,
                'status': 'success',
                'packet_count': len(packets)
            })
            
        except Exception as e:
            socketio.emit('analysis_complete', {
                'analysis_id': analysis_id,
                'status': 'error',
                'error': str(e)
            })
    
    # Start background thread
    thread = threading.Thread(target=run_analysis, args=(custom_args,))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "analysis_id": analysis_id,
        "status": "started",
        "message": "Analysis started in background"
    })
    


@app.route('/api/v1/signatures/generate', methods=['POST'])
@require_api_key
def api_generate_signatures():
    """Generate signatures from existing analysis"""
    data = request.get_json()
    analysis_id = data.get('analysis_id')
    
    if not analysis_id:
        return jsonify({"error": "No analysis_id provided"}), 400
    
    # Load analysis results
    analysis_path = Path(f'output/analysis/analysis_{analysis_id}.json')
    if not analysis_path.exists():
        analysis_path = Path(f'output/analysis/{analysis_id}.json')
    
    if not analysis_path.exists():
        return jsonify({"error": "Analysis not found"}), 404
    
    try:
        with open(analysis_path, 'r') as f:
            results = json.load(f)
        
        # Generate signatures
        with SignatureGenerator() as generator:
            generator.load_analysis_results(
                protocol_analysis=results.get('protocol_analysis'),
                exfiltration_results=results.get('exfiltration_detection')
            )
            generator.generate_signatures()
            report = generator.generate_report('json')
        
        return jsonify({
            "status": "success",
            "signatures": generator.get_results(),
            "report": report
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/file/<path:filepath>', methods=['GET'])
def api_read_file(filepath):
    # Normalize separators — browser may send forward slashes, OS uses backslashes
    filepath = filepath.replace('/', os.sep).replace('\\', os.sep)
    
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    full_path = os.path.abspath(os.path.join(BASE_DIR, filepath))

    if not full_path.startswith(BASE_DIR):
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.exists(full_path):
        return jsonify({"error": "File not found"}), 404

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return Response(content, mimetype='text/plain')
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/download/<path:filepath>', methods=['GET'])
def api_download_file(filepath):
    filepath = filepath.replace('/', os.sep).replace('\\', os.sep)
    
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    full_path = os.path.abspath(os.path.join(BASE_DIR, filepath))

    if not full_path.startswith(BASE_DIR):
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.exists(full_path):
        return jsonify({"error": "File not found"}), 404

    return send_file(full_path, as_attachment=True)

# ============================================================================
# WebSocket Events
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'data': 'Connected to PDR Dashboard'})


@socketio.on('subscribe_analysis')
def handle_subscribe_analysis(data):
    """Subscribe to analysis updates"""
    analysis_id = data.get('analysis_id')
    if analysis_id:
        emit('subscribed', {'analysis_id': analysis_id})


@socketio.on('start_capture')
def handle_start_capture(data):
    """Start live packet capture"""
    interface = data.get('interface', None)
    duration = data.get('duration', 30)
    
    def run_capture():
        capture_id = f"live_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        with PacketCapture() as capture:
            capture.start_capture(interface=interface, timeout=duration)
            
            # Stream packets in real-time
            start_time = time.time()
            while time.time() - start_time < duration:
                time.sleep(1)
                packets = capture.get_packets()
                socketio.emit('capture_update', {
                    'capture_id': capture_id,
                    'packet_count': len(packets),
                    'bytes': capture.captured_bytes,
                    'duration': time.time() - start_time
                })
            
            # Save capture
            pcap_file = capture.save_pcap()
            
            socketio.emit('capture_complete', {
                'capture_id': capture_id,
                'pcap_file': pcap_file,
                'packet_count': len(capture.get_packets())
            })
    
    thread = threading.Thread(target=run_capture)
    thread.daemon = True
    thread.start()
    
    emit('capture_started', {'status': 'started'})


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print(" PDR WEB DASHBOARD ")
    print("=" * 60)

    print(f"\n[OK] Dashboard starting...")
    print(f"[OK] URL: http://localhost:5000")
    print(f"[OK] API: http://localhost:5000/api/v1")
    print(f"\nPress Ctrl+C to stop")
    print("=" * 60)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, 
             use_reloader=True, reloader_options={'exclude_patterns': ['venv/*']})

