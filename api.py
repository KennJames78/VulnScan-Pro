"""
RESTful API interface for VulnScan-Pro
Enables integration with existing security infrastructure
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.exceptions import BadRequest, NotFound
import threading
import uuid

from scanner import VulnerabilityScanner
from reporting import ReportGenerator


class VulnScanAPI:
    """RESTful API for VulnScan-Pro vulnerability scanner"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        self.app = Flask(__name__)
        CORS(self.app)
        self.host = host
        self.port = port
        self.scanner = VulnerabilityScanner()
        self.report_generator = ReportGenerator()
        
        # Active scans tracking
        self.active_scans = {}
        self.scan_results = {}
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'version': '1.0.0'
            })
        
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            """Start a new vulnerability scan"""
            try:
                data = request.get_json()
                if not data or 'targets' not in data:
                    raise BadRequest('Missing targets in request body')
                
                targets = data['targets']
                if isinstance(targets, str):
                    targets = [targets]
                
                # Generate unique scan ID
                scan_id = str(uuid.uuid4())
                
                # Start scan in background thread
                scan_thread = threading.Thread(
                    target=self._run_scan,
                    args=(scan_id, targets, data.get('options', {}))
                )
                scan_thread.daemon = True
                scan_thread.start()
                
                self.active_scans[scan_id] = {
                    'status': 'running',
                    'targets': targets,
                    'started_at': datetime.now().isoformat(),
                    'thread': scan_thread
                }
                
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'started',
                    'targets': targets
                }), 202
                
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/api/scan/<scan_id>', methods=['GET'])
        def get_scan_status(scan_id):
            """Get scan status and results"""
            if scan_id not in self.active_scans and scan_id not in self.scan_results:
                raise NotFound('Scan not found')
            
            if scan_id in self.active_scans:
                scan_info = self.active_scans[scan_id]
                return jsonify({
                    'scan_id': scan_id,
                    'status': scan_info['status'],
                    'targets': scan_info['targets'],
                    'started_at': scan_info['started_at']
                })
            else:
                # Scan completed
                results = self.scan_results[scan_id]
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'completed',
                    'results': results
                })
        
        @self.app.route('/api/scans', methods=['GET'])
        def list_scans():
            """List all scans"""
            scans = []
            
            # Active scans
            for scan_id, scan_info in self.active_scans.items():
                scans.append({
                    'scan_id': scan_id,
                    'status': scan_info['status'],
                    'targets': scan_info['targets'],
                    'started_at': scan_info['started_at']
                })
            
            # Completed scans
            for scan_id, results in self.scan_results.items():
                scans.append({
                    'scan_id': scan_id,
                    'status': 'completed',
                    'targets': results.get('targets', []),
                    'started_at': results.get('scan_date', ''),
                    'vulnerabilities_found': sum(len(host.get('vulnerabilities', [])) 
                                               for host in results.get('hosts', []))
                })
            
            return jsonify({'scans': scans})
        
        @self.app.route('/api/scan/<scan_id>/report', methods=['POST'])
        def generate_report(scan_id):
            """Generate report for completed scan"""
            if scan_id not in self.scan_results:
                raise NotFound('Scan results not found')
            
            try:
                data = request.get_json() or {}
                report_format = data.get('format', 'json').lower()
                
                if report_format not in ['json', 'html', 'pdf']:
                    raise BadRequest('Invalid report format. Use json, html, or pdf')
                
                results = self.scan_results[scan_id]
                
                if report_format == 'json':
                    filepath = self.report_generator.generate_json_report(results)
                elif report_format == 'html':
                    filepath = self.report_generator.generate_html_report(results)
                else:  # pdf
                    filepath = self.report_generator.generate_pdf_report(results)
                
                return jsonify({
                    'report_path': filepath,
                    'format': report_format,
                    'generated_at': datetime.now().isoformat()
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/scan/<scan_id>/download/<report_format>', methods=['GET'])
        def download_report(scan_id, report_format):
            """Download report file"""
            if scan_id not in self.scan_results:
                raise NotFound('Scan results not found')
            
            try:
                results = self.scan_results[scan_id]
                
                if report_format == 'json':
                    filepath = self.report_generator.generate_json_report(results)
                    mimetype = 'application/json'
                elif report_format == 'html':
                    filepath = self.report_generator.generate_html_report(results)
                    mimetype = 'text/html'
                elif report_format == 'pdf':
                    filepath = self.report_generator.generate_pdf_report(results)
                    mimetype = 'application/pdf'
                else:
                    raise BadRequest('Invalid report format')
                
                return send_file(filepath, mimetype=mimetype, as_attachment=True)
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/targets/discover', methods=['POST'])
        def discover_targets():
            """Discover targets in network range"""
            try:
                data = request.get_json()
                if not data or 'network' not in data:
                    raise BadRequest('Missing network range in request body')
                
                network = data['network']
                discovered = asyncio.run(self.scanner.discover_hosts(network))
                
                return jsonify({
                    'network': network,
                    'discovered_hosts': discovered,
                    'count': len(discovered)
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/api/cve/<cve_id>', methods=['GET'])
        def get_cve_info(cve_id):
            """Get CVE information"""
            try:
                cve_info = asyncio.run(self.scanner.get_cve_details(cve_id))
                if not cve_info:
                    raise NotFound('CVE not found')
                
                return jsonify(cve_info)
                
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({'error': 'Endpoint not found'}), 404
        
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify({'error': 'Bad request'}), 400
        
        @self.app.errorhandler(500)
        def internal_error(error):
            return jsonify({'error': 'Internal server error'}), 500
    
    def _run_scan(self, scan_id: str, targets: List[str], options: Dict[str, Any]):
        """Run vulnerability scan in background"""
        try:
            # Update status
            self.active_scans[scan_id]['status'] = 'scanning'
            
            # Run the scan
            results = asyncio.run(self.scanner.scan_targets(targets, **options))
            
            # Store results
            self.scan_results[scan_id] = results
            
            # Remove from active scans
            del self.active_scans[scan_id]
            
        except Exception as e:
            # Mark scan as failed
            self.active_scans[scan_id]['status'] = 'failed'
            self.active_scans[scan_id]['error'] = str(e)
    
    def run(self, debug: bool = False):
        """Start the API server"""
        print(f"Starting VulnScan-Pro API server on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=debug, threaded=True)


if __name__ == '__main__':
    # Example usage and API documentation
    api = VulnScanAPI()
    
    print("""
    VulnScan-Pro API Server
    ======================
    
    Available endpoints:
    
    GET  /api/health                    - Health check
    POST /api/scan                      - Start new scan
    GET  /api/scan/<scan_id>            - Get scan status/results
    GET  /api/scans                     - List all scans
    POST /api/scan/<scan_id>/report     - Generate report
    GET  /api/scan/<scan_id>/download/<format> - Download report
    POST /api/targets/discover          - Discover network targets
    GET  /api/cve/<cve_id>              - Get CVE information
    
    Example requests:
    
    # Start scan
    curl -X POST http://localhost:5000/api/scan \
         -H "Content-Type: application/json" \
         -d '{"targets": ["192.168.1.0/24"], "options": {"port_range": "1-1000"}}'
    
    # Check scan status
    curl http://localhost:5000/api/scan/<scan_id>
    
    # Generate HTML report
    curl -X POST http://localhost:5000/api/scan/<scan_id>/report \
         -H "Content-Type: application/json" \
         -d '{"format": "html"}'
    """)
    
    api.run(debug=True)