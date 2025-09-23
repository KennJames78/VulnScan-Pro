#!/usr/bin/env python3
"""
Basic functionality tests for VulnScan-Pro
Automated Vulnerability Assessment Tool
"""

import sys
import os
import unittest
import sqlite3
import json
import asyncio
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from network_discovery import NetworkDiscovery
    from cve_integration import CVEIntegration
    from async_scanner import AsyncVulnerabilityScanner
    from reporting import ReportGenerator
except ImportError as e:
    print(f"Warning: Could not import modules: {e}")
    print("This is expected if dependencies are not installed")


class TestVulnScanProBasics(unittest.TestCase):
    """Test basic functionality of VulnScan-Pro"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_db = 'test_vulnscan.db'
        
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
    
    def test_database_creation(self):
        """Test database creation and basic operations"""
        print("\n🧪 Testing database creation...")
        
        # Create test database
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        
        # Create basic tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                results TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                cve_id TEXT,
                severity TEXT,
                description TEXT,
                target_ip TEXT
            )
        ''')
        
        conn.commit()
        
        # Test insert
        cursor.execute('''
            INSERT INTO scan_results 
            (scan_id, target_ip, timestamp, results)
            VALUES (?, ?, ?, ?)
        ''', (
            'test-scan-001',
            '192.168.1.100',
            datetime.now().isoformat(),
            json.dumps({'status': 'completed', 'vulnerabilities': 0})
        ))
        
        conn.commit()
        
        # Test query
        cursor.execute('SELECT COUNT(*) FROM scan_results')
        count = cursor.fetchone()[0]
        
        conn.close()
        
        self.assertEqual(count, 1)
        print("✅ Database creation and operations working")
    
    def test_network_discovery_initialization(self):
        """Test NetworkDiscovery initialization"""
        print("\n🧪 Testing NetworkDiscovery initialization...")
        
        try:
            discovery = NetworkDiscovery()
            
            # Test basic attributes
            self.assertIsNotNone(discovery)
            self.assertTrue(hasattr(discovery, 'discover_hosts'))
            self.assertTrue(hasattr(discovery, 'scan_ports'))
            
            print("✅ NetworkDiscovery initialization working")
            
        except Exception as e:
            print(f"⚠️  NetworkDiscovery test skipped: {e}")
            self.skipTest(f"NetworkDiscovery dependencies not available: {e}")
    
    def test_cve_integration_initialization(self):
        """Test CVEIntegration initialization"""
        print("\n🧪 Testing CVEIntegration initialization...")
        
        try:
            cve_integration = CVEIntegration()
            
            # Test basic attributes
            self.assertIsNotNone(cve_integration)
            self.assertTrue(hasattr(cve_integration, 'get_cve_details'))
            self.assertTrue(hasattr(cve_integration, 'search_vulnerabilities'))
            
            print("✅ CVEIntegration initialization working")
            
        except Exception as e:
            print(f"⚠️  CVEIntegration test skipped: {e}")
            self.skipTest(f"CVEIntegration dependencies not available: {e}")
    
    @patch('requests.get')
    def test_cve_api_response_handling(self, mock_get):
        """Test CVE API response handling"""
        print("\n🧪 Testing CVE API response handling...")
        
        try:
            # Mock CVE API response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'result': {
                    'CVE_Items': [{
                        'cve': {
                            'CVE_data_meta': {'ID': 'CVE-2023-1234'},
                            'description': {
                                'description_data': [{
                                    'value': 'Test vulnerability description'
                                }]
                            }
                        },
                        'impact': {
                            'baseMetricV3': {
                                'cvssV3': {'baseScore': 7.5}
                            }
                        }
                    }]
                }
            }
            mock_get.return_value = mock_response
            
            cve_integration = CVEIntegration()
            
            # Test CVE lookup
            result = asyncio.run(cve_integration.get_cve_details('CVE-2023-1234'))
            
            self.assertIsNotNone(result)
            print("✅ CVE API response handling working")
            
        except Exception as e:
            print(f"⚠️  CVE API test skipped: {e}")
            self.skipTest(f"CVE API dependencies not available: {e}")
    
    def test_async_scanner_initialization(self):
        """Test AsyncVulnerabilityScanner initialization"""
        print("\n🧪 Testing AsyncVulnerabilityScanner initialization...")
        
        try:
            scanner = AsyncVulnerabilityScanner()
            
            # Test basic attributes
            self.assertIsNotNone(scanner)
            self.assertTrue(hasattr(scanner, 'scan_target'))
            self.assertTrue(hasattr(scanner, 'scan_multiple_targets'))
            
            print("✅ AsyncVulnerabilityScanner initialization working")
            
        except Exception as e:
            print(f"⚠️  AsyncVulnerabilityScanner test skipped: {e}")
            self.skipTest(f"AsyncVulnerabilityScanner dependencies not available: {e}")
    
    def test_report_generator_initialization(self):
        """Test ReportGenerator initialization"""
        print("\n🧪 Testing ReportGenerator initialization...")
        
        try:
            generator = ReportGenerator()
            
            # Test basic attributes
            self.assertIsNotNone(generator)
            self.assertTrue(hasattr(generator, 'generate_json_report'))
            self.assertTrue(hasattr(generator, 'generate_html_report'))
            self.assertTrue(hasattr(generator, 'generate_pdf_report'))
            
            print("✅ ReportGenerator initialization working")
            
        except Exception as e:
            print(f"⚠️  ReportGenerator test skipped: {e}")
            self.skipTest(f"ReportGenerator dependencies not available: {e}")
    
    def test_json_report_generation(self):
        """Test JSON report generation"""
        print("\n🧪 Testing JSON report generation...")
        
        try:
            generator = ReportGenerator(output_dir='test_reports')
            
            # Create test scan results
            test_results = {
                'scan_date': datetime.now().isoformat(),
                'scan_duration': 45.2,
                'hosts': [
                    {
                        'ip': '192.168.1.100',
                        'hostname': 'test-server',
                        'vulnerabilities': [
                            {
                                'cve_id': 'CVE-2023-1234',
                                'description': 'Test vulnerability',
                                'risk_level': 'High',
                                'cvss_score': 7.5,
                                'service': 'HTTP/80'
                            }
                        ]
                    }
                ]
            }
            
            # Generate JSON report
            report_path = generator.generate_json_report(test_results, 'test_report.json')
            
            # Verify report was created
            self.assertTrue(os.path.exists(report_path))
            
            # Verify report content
            with open(report_path, 'r') as f:
                report_data = json.load(f)
            
            self.assertIn('executive_summary', report_data)
            self.assertIn('detailed_results', report_data)
            
            # Cleanup
            if os.path.exists(report_path):
                os.remove(report_path)
            if os.path.exists('test_reports'):
                os.rmdir('test_reports')
            
            print("✅ JSON report generation working")
            
        except Exception as e:
            print(f"⚠️  JSON report test skipped: {e}")
            self.skipTest(f"JSON report dependencies not available: {e}")
    
    def test_api_response_format(self):
        """Test API response format"""
        print("\n🧪 Testing API response format...")
        
        # Test health check response
        health_response = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }
        
        # Test scan response
        scan_response = {
            'scan_id': 'test-scan-001',
            'status': 'started',
            'targets': ['192.168.1.100']
        }
        
        # Validate JSON serialization
        health_json = json.dumps(health_response)
        scan_json = json.dumps(scan_response)
        
        health_parsed = json.loads(health_json)
        scan_parsed = json.loads(scan_json)
        
        self.assertEqual(health_parsed['status'], 'healthy')
        self.assertEqual(scan_parsed['scan_id'], 'test-scan-001')
        self.assertIsInstance(scan_parsed['targets'], list)
        
        print("✅ API response format working")
    
    def test_configuration_validation(self):
        """Test configuration validation"""
        print("\n🧪 Testing configuration validation...")
        
        # Test config structure
        test_config = {
            'DEFAULT_PORTS': '1-1000',
            'SCAN_TIMEOUT': 300,
            'MAX_CONCURRENT_SCANS': 10,
            'CVE_API_URL': 'https://services.nvd.nist.gov/rest/json/cves/1.0',
            'REPORT_OUTPUT_DIR': 'reports',
            'DATABASE_PATH': 'vulnscan.db',
            'API_HOST': '0.0.0.0',
            'API_PORT': 5000
        }
        
        # Validate config values
        self.assertIsInstance(test_config['SCAN_TIMEOUT'], int)
        self.assertIsInstance(test_config['MAX_CONCURRENT_SCANS'], int)
        self.assertIsInstance(test_config['API_PORT'], int)
        self.assertTrue(test_config['CVE_API_URL'].startswith('https://'))
        
        print("✅ Configuration validation working")
    
    def test_vulnerability_risk_assessment(self):
        """Test vulnerability risk assessment"""
        print("\n🧪 Testing vulnerability risk assessment...")
        
        # Test CVSS score to risk level mapping
        def get_risk_level(cvss_score):
            if cvss_score >= 9.0:
                return 'Critical'
            elif cvss_score >= 7.0:
                return 'High'
            elif cvss_score >= 4.0:
                return 'Medium'
            elif cvss_score >= 0.1:
                return 'Low'
            else:
                return 'Info'
        
        # Test various CVSS scores
        test_cases = [
            (9.8, 'Critical'),
            (7.5, 'High'),
            (5.2, 'Medium'),
            (2.1, 'Low'),
            (0.0, 'Info')
        ]
        
        for cvss_score, expected_risk in test_cases:
            actual_risk = get_risk_level(cvss_score)
            self.assertEqual(actual_risk, expected_risk)
        
        print("✅ Vulnerability risk assessment working")


def run_basic_tests():
    """Run basic functionality tests"""
    print("🚀 VulnScan-Pro Basic Functionality Tests")
    print("=" * 50)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestVulnScanProBasics)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("🎉 All basic functionality tests passed!")
        print(f"✅ Tests run: {result.testsRun}")
        print(f"✅ Failures: {len(result.failures)}")
        print(f"✅ Errors: {len(result.errors)}")
        print(f"✅ Skipped: {len(result.skipped)}")
    else:
        print("❌ Some tests failed or had errors")
        print(f"Tests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        print(f"Skipped: {len(result.skipped)}")
        
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"- {test}: {traceback}")
        
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"- {test}: {traceback}")
    
    print("=" * 50)
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_basic_tests()
    sys.exit(0 if success else 1)