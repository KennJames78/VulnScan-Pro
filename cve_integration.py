#!/usr/bin/env python3
"""
VulnScan-Pro: CVE API Integration Module
Real-time vulnerability identification and risk assessment
"""

import requests
import json
import sqlite3
import asyncio
import aiohttp
from datetime import datetime, timedelta
import re
import logging
from typing import Dict, List, Optional
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CVEIntegration:
    def __init__(self, db_path='vulnscan_results.db'):
        self.db_path = db_path
        self.cve_cache = {}
        self.api_endpoints = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'circl': 'https://cve.circl.lu/api/cve',
            'cvedetails': 'https://www.cvedetails.com/json-feed.php'
        }
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1.0  # 1 second between requests
        
        # Initialize database
        self.init_cve_database()
        
    def init_cve_database(self):
        """Initialize CVE database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                description TEXT,
                cvss_v3_score REAL,
                cvss_v2_score REAL,
                severity TEXT,
                attack_vector TEXT,
                attack_complexity TEXT,
                privileges_required TEXT,
                user_interaction TEXT,
                scope TEXT,
                confidentiality_impact TEXT,
                integrity_impact TEXT,
                availability_impact TEXT,
                published_date TEXT,
                modified_date TEXT,
                references TEXT,
                cpe_matches TEXT,
                cached_date TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER,
                service_name TEXT,
                service_version TEXT,
                cve_id TEXT NOT NULL,
                match_confidence REAL,
                match_reason TEXT,
                discovery_time TEXT NOT NULL,
                FOREIGN KEY (cve_id) REFERENCES cve_data (cve_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cpe_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER,
                cpe_string TEXT NOT NULL,
                product TEXT,
                vendor TEXT,
                version TEXT,
                discovery_time TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("CVE database tables initialized")

    def rate_limit(self):
        """Implement rate limiting for API requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()

    def search_cve_by_keyword(self, keywords: List[str], limit: int = 50) -> List[Dict]:
        """Search CVEs by keywords using NVD API"""
        logger.info(f"Searching CVEs for keywords: {keywords}")
        
        results = []
        
        for keyword in keywords:
            self.rate_limit()
            
            try:
                params = {
                    'keywordSearch': keyword,
                    'resultsPerPage': min(limit, 2000),
                    'startIndex': 0
                }
                
                response = requests.get(self.api_endpoints['nvd'], params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        cve_data = self.parse_nvd_vulnerability(vuln)
                        if cve_data:
                            results.append(cve_data)
                            # Cache the result
                            self.cache_cve_data(cve_data)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error searching CVE for keyword '{keyword}': {e}")
                continue
        
        logger.info(f"Found {len(results)} CVEs for keywords: {keywords}")
        return results

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get detailed CVE information"""
        # Check cache first
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        # Check database cache
        cached_cve = self.get_cached_cve(cve_id)
        if cached_cve:
            self.cve_cache[cve_id] = cached_cve
            return cached_cve
        
        # Fetch from API
        self.rate_limit()
        
        try:
            params = {
                'cveId': cve_id
            }
            
            response = requests.get(self.api_endpoints['nvd'], params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if 'vulnerabilities' in data and data['vulnerabilities']:
                cve_data = self.parse_nvd_vulnerability(data['vulnerabilities'][0])
                if cve_data:
                    self.cache_cve_data(cve_data)
                    self.cve_cache[cve_id] = cve_data
                    return cve_data
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
        
        return None

    def parse_nvd_vulnerability(self, vuln_data: Dict) -> Optional[Dict]:
        """Parse NVD vulnerability data"""
        try:
            cve = vuln_data['cve']
            cve_id = cve['id']
            
            # Extract description
            description = ''
            if 'descriptions' in cve:
                for desc in cve['descriptions']:
                    if desc['lang'] == 'en':
                        description = desc['value']
                        break
            
            # Extract CVSS scores
            cvss_v3_score = None
            cvss_v2_score = None
            severity = 'UNKNOWN'
            metrics = {}
            
            if 'metrics' in cve:
                # CVSS v3
                if 'cvssMetricV31' in cve['metrics']:
                    cvss_v3 = cve['metrics']['cvssMetricV31'][0]['cvssData']
                    cvss_v3_score = cvss_v3['baseScore']
                    severity = cve['metrics']['cvssMetricV31'][0]['baseSeverity']
                    metrics.update({
                        'attack_vector': cvss_v3.get('attackVector'),
                        'attack_complexity': cvss_v3.get('attackComplexity'),
                        'privileges_required': cvss_v3.get('privilegesRequired'),
                        'user_interaction': cvss_v3.get('userInteraction'),
                        'scope': cvss_v3.get('scope'),
                        'confidentiality_impact': cvss_v3.get('confidentialityImpact'),
                        'integrity_impact': cvss_v3.get('integrityImpact'),
                        'availability_impact': cvss_v3.get('availabilityImpact')
                    })
                
                # CVSS v2 fallback
                elif 'cvssMetricV2' in cve['metrics']:
                    cvss_v2 = cve['metrics']['cvssMetricV2'][0]['cvssData']
                    cvss_v2_score = cvss_v2['baseScore']
                    severity = cve['metrics']['cvssMetricV2'][0]['baseSeverity']
            
            # Extract references
            references = []
            if 'references' in cve:
                for ref in cve['references']:
                    references.append({
                        'url': ref['url'],
                        'source': ref.get('source', ''),
                        'tags': ref.get('tags', [])
                    })
            
            # Extract CPE matches
            cpe_matches = []
            if 'configurations' in cve:
                for config in cve['configurations']:
                    if 'nodes' in config:
                        for node in config['nodes']:
                            if 'cpeMatch' in node:
                                for cpe_match in node['cpeMatch']:
                                    if cpe_match.get('vulnerable', False):
                                        cpe_matches.append({
                                            'cpe23Uri': cpe_match['criteria'],
                                            'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                                            'versionEndExcluding': cpe_match.get('versionEndExcluding'),
                                            'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                                            'versionEndIncluding': cpe_match.get('versionEndIncluding')
                                        })
            
            # Extract dates
            published_date = cve.get('published', '')
            modified_date = cve.get('lastModified', '')
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_v3_score': cvss_v3_score,
                'cvss_v2_score': cvss_v2_score,
                'severity': severity,
                'published_date': published_date,
                'modified_date': modified_date,
                'references': references,
                'cpe_matches': cpe_matches,
                **metrics
            }
        
        except Exception as e:
            logger.error(f"Error parsing vulnerability data: {e}")
            return None

    def generate_cpe_string(self, vendor: str, product: str, version: str) -> str:
        """Generate CPE 2.3 string from service information"""
        # Clean and normalize inputs
        vendor = re.sub(r'[^a-zA-Z0-9._-]', '', vendor.lower()) if vendor else '*'
        product = re.sub(r'[^a-zA-Z0-9._-]', '', product.lower()) if product else '*'
        version = re.sub(r'[^a-zA-Z0-9._-]', '', version.lower()) if version else '*'
        
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    def match_service_to_cves(self, service_info: Dict) -> List[Dict]:
        """Match service information to known CVEs"""
        matches = []
        
        # Extract service details
        service_name = service_info.get('service', '').lower()
        product = service_info.get('product', '').lower()
        version = service_info.get('version', '').lower()
        
        # Generate search keywords
        keywords = []
        if product:
            keywords.append(product)
        if service_name and service_name != product:
            keywords.append(service_name)
        
        if not keywords:
            return matches
        
        # Search for CVEs
        cve_results = self.search_cve_by_keyword(keywords, limit=100)
        
        for cve in cve_results:
            confidence = self.calculate_match_confidence(service_info, cve)
            if confidence > 0.3:  # Minimum confidence threshold
                match = {
                    'cve_id': cve['cve_id'],
                    'confidence': confidence,
                    'reason': self.generate_match_reason(service_info, cve),
                    'cve_data': cve
                }
                matches.append(match)
        
        # Sort by confidence
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        
        return matches[:20]  # Return top 20 matches

    def calculate_match_confidence(self, service_info: Dict, cve_data: Dict) -> float:
        """Calculate confidence score for CVE match"""
        confidence = 0.0
        
        service_name = service_info.get('service', '').lower()
        product = service_info.get('product', '').lower()
        version = service_info.get('version', '').lower()
        
        description = cve_data.get('description', '').lower()
        cpe_matches = cve_data.get('cpe_matches', [])
        
        # Check product name in description
        if product and product in description:
            confidence += 0.4
        
        # Check service name in description
        if service_name and service_name in description:
            confidence += 0.3
        
        # Check CPE matches
        for cpe_match in cpe_matches:
            cpe_uri = cpe_match.get('cpe23Uri', '').lower()
            
            if product and product in cpe_uri:
                confidence += 0.5
                
                # Version matching
                if version:
                    if version in cpe_uri:
                        confidence += 0.3
                    elif self.version_in_range(version, cpe_match):
                        confidence += 0.2
        
        # Boost confidence for exact matches
        if confidence > 0.8:
            confidence = min(1.0, confidence * 1.1)
        
        return min(1.0, confidence)

    def version_in_range(self, version: str, cpe_match: Dict) -> bool:
        """Check if version falls within CPE match range"""
        try:
            # Simple version comparison (can be enhanced)
            start_including = cpe_match.get('versionStartIncluding')
            end_excluding = cpe_match.get('versionEndExcluding')
            start_excluding = cpe_match.get('versionStartExcluding')
            end_including = cpe_match.get('versionEndIncluding')
            
            # Basic string comparison (should be enhanced with proper version parsing)
            if start_including and version < start_including:
                return False
            if end_excluding and version >= end_excluding:
                return False
            if start_excluding and version <= start_excluding:
                return False
            if end_including and version > end_including:
                return False
            
            return True
        except:
            return False

    def generate_match_reason(self, service_info: Dict, cve_data: Dict) -> str:
        """Generate human-readable match reason"""
        reasons = []
        
        product = service_info.get('product', '')
        version = service_info.get('version', '')
        description = cve_data.get('description', '')
        
        if product and product.lower() in description.lower():
            reasons.append(f"Product '{product}' mentioned in CVE description")
        
        for cpe_match in cve_data.get('cpe_matches', []):
            cpe_uri = cpe_match.get('cpe23Uri', '')
            if product and product.lower() in cpe_uri.lower():
                reasons.append(f"Product '{product}' found in CPE configuration")
                if version and version in cpe_uri:
                    reasons.append(f"Version '{version}' matches CPE version")
                break
        
        return '; '.join(reasons) if reasons else 'Keyword match in CVE data'

    def cache_cve_data(self, cve_data: Dict):
        """Cache CVE data in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO cve_data 
            (cve_id, description, cvss_v3_score, cvss_v2_score, severity,
             attack_vector, attack_complexity, privileges_required, user_interaction,
             scope, confidentiality_impact, integrity_impact, availability_impact,
             published_date, modified_date, references, cpe_matches, cached_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cve_data['cve_id'],
            cve_data.get('description', ''),
            cve_data.get('cvss_v3_score'),
            cve_data.get('cvss_v2_score'),
            cve_data.get('severity', ''),
            cve_data.get('attack_vector', ''),
            cve_data.get('attack_complexity', ''),
            cve_data.get('privileges_required', ''),
            cve_data.get('user_interaction', ''),
            cve_data.get('scope', ''),
            cve_data.get('confidentiality_impact', ''),
            cve_data.get('integrity_impact', ''),
            cve_data.get('availability_impact', ''),
            cve_data.get('published_date', ''),
            cve_data.get('modified_date', ''),
            json.dumps(cve_data.get('references', [])),
            json.dumps(cve_data.get('cpe_matches', [])),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()

    def get_cached_cve(self, cve_id: str) -> Optional[Dict]:
        """Get cached CVE data from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM cve_data WHERE cve_id = ?', (cve_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            # Check if cache is still valid (30 days)
            cached_date = datetime.fromisoformat(result[17])
            if datetime.now() - cached_date < timedelta(days=30):
                return {
                    'cve_id': result[1],
                    'description': result[2],
                    'cvss_v3_score': result[3],
                    'cvss_v2_score': result[4],
                    'severity': result[5],
                    'attack_vector': result[6],
                    'attack_complexity': result[7],
                    'privileges_required': result[8],
                    'user_interaction': result[9],
                    'scope': result[10],
                    'confidentiality_impact': result[11],
                    'integrity_impact': result[12],
                    'availability_impact': result[13],
                    'published_date': result[14],
                    'modified_date': result[15],
                    'references': json.loads(result[16]) if result[16] else [],
                    'cpe_matches': json.loads(result[17]) if result[17] else []
                }
        
        return None

    def store_vulnerability_match(self, session_id: str, ip_address: str, port: int, 
                                service_info: Dict, match: Dict):
        """Store vulnerability match in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerability_matches 
            (session_id, ip_address, port, service_name, service_version, 
             cve_id, match_confidence, match_reason, discovery_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            ip_address,
            port,
            service_info.get('service', ''),
            service_info.get('version', ''),
            match['cve_id'],
            match['confidence'],
            match['reason'],
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()

    async def async_vulnerability_scan(self, services: List[Dict], session_id: str) -> Dict:
        """Perform asynchronous vulnerability scanning"""
        logger.info(f"Starting async vulnerability scan for {len(services)} services")
        
        results = {
            'total_services': len(services),
            'vulnerabilities_found': 0,
            'high_risk_vulns': 0,
            'critical_vulns': 0,
            'matches': []
        }
        
        semaphore = asyncio.Semaphore(5)  # Limit concurrent requests
        
        async def scan_service(service):
            async with semaphore:
                # Run synchronous CVE matching in thread pool
                loop = asyncio.get_event_loop()
                matches = await loop.run_in_executor(None, self.match_service_to_cves, service)
                
                for match in matches:
                    if match['confidence'] > 0.5:  # Only store high-confidence matches
                        self.store_vulnerability_match(
                            session_id,
                            service.get('ip_address', ''),
                            service.get('port', 0),
                            service,
                            match
                        )
                        
                        results['matches'].append({
                            'service': service,
                            'match': match
                        })
                        
                        # Count severity levels
                        severity = match['cve_data'].get('severity', '').upper()
                        if severity == 'CRITICAL':
                            results['critical_vulns'] += 1
                        elif severity == 'HIGH':
                            results['high_risk_vulns'] += 1
                
                return matches
        
        # Create tasks for all services
        tasks = [scan_service(service) for service in services]
        
        # Execute scans concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
        
        results['vulnerabilities_found'] = len(results['matches'])
        
        logger.info(f"Vulnerability scan completed. Found {results['vulnerabilities_found']} vulnerabilities")
        return results

    def get_vulnerability_summary(self, session_id: str) -> Dict:
        """Get vulnerability summary for session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get vulnerability counts by severity
        cursor.execute('''
            SELECT c.severity, COUNT(*) as count
            FROM vulnerability_matches v
            JOIN cve_data c ON v.cve_id = c.cve_id
            WHERE v.session_id = ?
            GROUP BY c.severity
        ''', (session_id,))
        
        severity_counts = dict(cursor.fetchall())
        
        # Get top vulnerabilities
        cursor.execute('''
            SELECT v.*, c.description, c.cvss_v3_score, c.severity
            FROM vulnerability_matches v
            JOIN cve_data c ON v.cve_id = c.cve_id
            WHERE v.session_id = ?
            ORDER BY c.cvss_v3_score DESC, v.match_confidence DESC
            LIMIT 10
        ''', (session_id,))
        
        top_vulnerabilities = cursor.fetchall()
        
        conn.close()
        
        return {
            'severity_counts': severity_counts,
            'top_vulnerabilities': top_vulnerabilities,
            'total_vulnerabilities': sum(severity_counts.values())
        }

if __name__ == '__main__':
    # Example usage
    cve_integration = CVEIntegration()
    
    # Test service matching
    test_service = {
        'service': 'http',
        'product': 'Apache',
        'version': '2.4.41',
        'port': 80,
        'ip_address': '192.168.1.100'
    }
    
    print(f"Testing CVE matching for: {test_service}")
    matches = cve_integration.match_service_to_cves(test_service)
    
    print(f"Found {len(matches)} potential vulnerabilities:")
    for match in matches[:5]:
        cve_data = match['cve_data']
        print(f"  - {cve_data['cve_id']}: {cve_data.get('severity', 'UNKNOWN')} "
              f"(Confidence: {match['confidence']:.2f})")
        print(f"    {cve_data['description'][:100]}...")
