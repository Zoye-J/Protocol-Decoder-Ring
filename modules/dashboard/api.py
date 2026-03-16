"""
Extended REST API for PDR Dashboard
Additional API endpoints beyond the basic ones in app.py
"""

from flask import Blueprint, jsonify, request, send_file
from datetime import datetime, timedelta
from pathlib import Path
import json
import csv
import io

api_bp = Blueprint('api', __name__, url_prefix='/api/v2')


@api_bp.route('/export/analysis/<analysis_id>', methods=['GET'])
def export_analysis(analysis_id):
    """Export analysis results in various formats"""
    format_type = request.args.get('format', 'json')
    
    # Find analysis file
    analysis_path = Path(f'output/analysis/analysis_{analysis_id}.json')
    if not analysis_path.exists():
        analysis_path = Path(f'output/analysis/{analysis_id}.json')
    
    if not analysis_path.exists():
        return jsonify({"error": "Analysis not found"}), 404
    
    # Load analysis data
    with open(analysis_path, 'r') as f:
        data = json.load(f)
    
    if format_type == 'json':
        return send_file(analysis_path, as_attachment=True, 
                        download_name=f'analysis_{analysis_id}.json')
    
    elif format_type == 'csv':
        # Convert to CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['Timestamp', 'Type', 'Severity', 'Description', 'Source', 'Destination'])
        
        # Write alerts
        for alert in data.get('alerts', []):
            writer.writerow([
                alert.get('timestamp', ''),
                alert.get('type', ''),
                alert.get('severity', ''),
                alert.get('description', ''),
                alert.get('details', {}).get('src_ip', ''),
                alert.get('details', {}).get('dst_ip', '')
            ])
        
        # Create response
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=analysis_{analysis_id}.csv'}
        )
    
    elif format_type == 'html':
        # Generate HTML report
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Analysis Report {analysis_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #0d6efd; }}
                .alert {{ padding: 10px; margin: 5px 0; border-radius: 5px; }}
                .high {{ background-color: #f8d7da; border-left: 4px solid #dc3545; }}
                .medium {{ background-color: #fff3cd; border-left: 4px solid #ffc107; }}
                .low {{ background-color: #d1e7dd; border-left: 4px solid #198754; }}
            </style>
        </head>
        <body>
            <h1>Analysis Report: {analysis_id}</h1>
            <p>Generated: {datetime.now().isoformat()}</p>
            
            <h2>Statistics</h2>
            <ul>
                <li>Total Packets: {data.get('statistics', {}).get('total_packets', 0)}</li>
                <li>Total Bytes: {data.get('statistics', {}).get('total_bytes', 0)}</li>
                <li>Total Alerts: {len(data.get('alerts', []))}</li>
            </ul>
            
            <h2>Alerts</h2>
            {''.join(f'<div class="alert {a.get("severity", "low")}">'
                    f'<strong>{a.get("type")}</strong>: {a.get("description")}'
                    f'</div>' for a in data.get('alerts', []))}
        </body>
        </html>
        """
        
        return Response(html, mimetype='text/html',
                       headers={'Content-Disposition': f'attachment; filename=analysis_{analysis_id}.html'})


@api_bp.route('/search', methods=['GET'])
def search():
    """Search across all analyses"""
    query = request.args.get('q', '').lower()
    limit = request.args.get('limit', 50, type=int)
    
    results = {
        'analyses': [],
        'alerts': [],
        'signatures': []
    }
    
    if not query:
        return jsonify(results)
    
    # Search analyses
    output_dir = Path('output/analysis')
    if output_dir.exists():
        for file in output_dir.glob('*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    
                    # Check if query matches analysis ID
                    if query in data.get('analysis_id', '').lower():
                        results['analyses'].append({
                            'id': data.get('analysis_id'),
                            'file': file.name,
                            'timestamp': data.get('timestamp')
                        })
                    
                    # Search in alerts
                    for alert in data.get('alerts', []):
                        if (query in alert.get('type', '').lower() or 
                            query in alert.get('description', '').lower()):
                            results['alerts'].append({
                                'type': alert.get('type'),
                                'severity': alert.get('severity'),
                                'analysis_id': data.get('analysis_id')
                            })
            except:
                pass
    
    # Search signatures
    sig_dir = Path('signatures/custom')
    if sig_dir.exists():
        for file in sig_dir.glob('*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    if query in data.get('signature_id', '').lower():
                        results['signatures'].append({
                            'id': data.get('signature_id'),
                            'file': file.name
                        })
            except:
                pass
    
    # Apply limits
    results['analyses'] = results['analyses'][:limit]
    results['alerts'] = results['alerts'][:limit]
    results['signatures'] = results['signatures'][:limit]
    
    return jsonify(results)


@api_bp.route('/stats/summary', methods=['GET'])
def stats_summary():
    """Get summary statistics"""
    days = request.args.get('days', 7, type=int)
    since = datetime.now() - timedelta(days=days)
    
    stats = {
        'total_analyses': 0,
        'total_alerts': 0,
        'alerts_by_day': {},
        'top_alerts': [],
        'storage_used': 0
    }
    
    # Calculate storage
    for dir_path in ['output', 'signatures', 'reports']:
        path = Path(dir_path)
        if path.exists():
            for file in path.glob('**/*'):
                if file.is_file():
                    stats['storage_used'] += file.stat().st_size
    
    stats['storage_used'] = round(stats['storage_used'] / (1024 * 1024), 2)
    
    # Count analyses and alerts
    output_dir = Path('output/analysis')
    if output_dir.exists():
        for file in output_dir.glob('*.json'):
            try:
                mod_time = datetime.fromtimestamp(file.stat().st_mtime)
                if mod_time > since:
                    stats['total_analyses'] += 1
                    
                    with open(file, 'r') as f:
                        data = json.load(f)
                        alert_count = len(data.get('alerts', []))
                        stats['total_alerts'] += alert_count
                        
                        # Group by day
                        day = mod_time.strftime('%Y-%m-%d')
                        stats['alerts_by_day'][day] = stats['alerts_by_day'].get(day, 0) + alert_count
            except:
                pass
    
    return jsonify(stats)


@api_bp.route('/compare', methods=['POST'])
def compare_analyses():
    """Compare multiple analyses"""
    data = request.get_json()
    analysis_ids = data.get('analysis_ids', [])
    
    if len(analysis_ids) < 2:
        return jsonify({"error": "Need at least 2 analysis IDs"}), 400
    
    analyses = []
    for aid in analysis_ids:
        # Load each analysis
        path = Path(f'output/analysis/analysis_{aid}.json')
        if not path.exists():
            path = Path(f'output/analysis/{aid}.json')
        
        if path.exists():
            with open(path, 'r') as f:
                analyses.append(json.load(f))
    
    if len(analyses) < 2:
        return jsonify({"error": "Could not load analyses"}), 404
    
    # Compare
    comparison = {
        'analyses': [a.get('analysis_id') for a in analyses],
        'timestamps': [a.get('timestamp') for a in analyses],
        'packet_counts': [a.get('statistics', {}).get('total_packets', 0) for a in analyses],
        'alert_counts': [len(a.get('alerts', [])) for a in analyses],
        'common_alerts': [],
        'unique_alerts': {}
    }
    
    # Find common alert types
    all_alerts = {}
    for i, analysis in enumerate(analyses):
        analysis_id = comparison['analyses'][i]
        comparison['unique_alerts'][analysis_id] = []
        
        for alert in analysis.get('alerts', []):
            alert_type = alert.get('type')
            if alert_type not in all_alerts:
                all_alerts[alert_type] = set()
            all_alerts[alert_type].add(i)
    
    # Categorize
    for alert_type, indices in all_alerts.items():
        if len(indices) == len(analyses):
            comparison['common_alerts'].append(alert_type)
        else:
            for i in indices:
                aid = comparison['analyses'][i]
                comparison['unique_alerts'][aid].append(alert_type)
    
    return jsonify(comparison)


# Register blueprint in app.py
# app.register_blueprint(api_bp)