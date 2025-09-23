#!/usr/bin/env python3
"""
VulnScan-Pro: Network Discovery Module
Automated network discovery and service enumeration with Nmap
"""

import nmap
import asyncio
import json
import sqlite3
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkDiscovery:
    def __init__(self, db_path='vulnscan_results.db'):
        self.nm = nmap.PortScanner()
        self.db_path = db_path
        self.discovered_hosts = {}
        self.scan_results = {}
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing scan results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                target_range TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                mac_address TEXT,
                vendor TEXT,
                os_name TEXT,
                os_accuracy INTEGER,
                status TEXT NOT NULL,
                discovery_time TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS discovered_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT,
                service_version TEXT,
                service_product TEXT,
                service_extrainfo TEXT,
                state TEXT NOT NULL,
                reason TEXT,
                discovery_time TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER,
                service_name TEXT,
                cve_id TEXT,
                cvss_score REAL,
                severity TEXT,
                description TEXT,
                solution TEXT,
                references TEXT,
                discovery_time TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions (session_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")

    def validate_target(self, target):
        """Validate target IP range or hostname"""
        try:
            # Try to parse as IP network
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            try:
                # Try to parse as single IP
                ipaddress.ip_address(target)
                return True
            except ValueError:
                # Assume it's a hostname
                return True

    def ping_sweep(self, target_range, session_id):
        """Perform ping sweep to discover live hosts"""
        logger.info(f"Starting ping sweep for {target_range}")
        
        try:
            # Perform ping scan
            self.nm.scan(hosts=target_range, arguments='-sn -PE -PP -PM')
            
            live_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = {
                        'ip': host,
                        'hostname': self.nm[host].hostname() if self.nm[host].hostname() else None,
                        'status': 'up',
                        'mac': None,
                        'vendor': None
                    }
                    
                    # Get MAC address if available
                    if 'mac' in self.nm[host]['addresses']:
                        host_info['mac'] = self.nm[host]['addresses']['mac']
                        
                    # Get vendor info if available
                    if 'vendor' in self.nm[host] and host_info['mac']:
                        vendor_info = self.nm[host]['vendor']
                        if host_info['mac'] in vendor_info:
                            host_info['vendor'] = vendor_info[host_info['mac']]
                    
                    live_hosts.append(host_info)
                    self.discovered_hosts[host] = host_info
                    
                    # Store in database
                    self.store_discovered_host(session_id, host_info)
            
            logger.info(f"Ping sweep completed. Found {len(live_hosts)} live hosts")
            return live_hosts
            
        except Exception as e:
            logger.error(f"Error during ping sweep: {e}")
            return []

    def port_scan(self, target, ports='1-1000', scan_type='syn', session_id=None):
        """Perform port scan on target"""
        logger.info(f"Starting port scan on {target} (ports: {ports}, type: {scan_type})")
        
        # Map scan types to nmap arguments
        scan_args = {
            'syn': '-sS',
            'tcp': '-sT',
            'udp': '-sU',
            'comprehensive': '-sS -sV -O --script=default',
            'stealth': '-sS -f -T2',
            'aggressive': '-sS -sV -O -A --script=vuln'
        }
        
        nmap_args = scan_args.get(scan_type, '-sS')
        
        try:
            # Perform port scan
            self.nm.scan(hosts=target, ports=ports, arguments=nmap_args)
            
            scan_results = {}
            
            for host in self.nm.all_hosts():
                host_results = {
                    'ip': host,
                    'hostname': self.nm[host].hostname(),
                    'status': self.nm[host].state(),
                    'protocols': {},
                    'os': {},
                    'services': []
                }
                
                # Get OS information if available
                if 'osmatch' in self.nm[host]:
                    os_matches = self.nm[host]['osmatch']
                    if os_matches:
                        best_match = max(os_matches, key=lambda x: int(x['accuracy']))
                        host_results['os'] = {
                            'name': best_match['name'],
                            'accuracy': int(best_match['accuracy'])
                        }
                
                # Process each protocol
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    host_results['protocols'][protocol] = {}
                    
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        service_info = {
                            'state': port_info['state'],
                            'reason': port_info['reason'],
                            'name': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        
                        host_results['protocols'][protocol][port] = service_info
                        
                        # Add to services list for easier access
                        if port_info['state'] == 'open':
                            service_entry = {
                                'port': port,
                                'protocol': protocol,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', '')
                            }
                            host_results['services'].append(service_entry)
                            
                            # Store service in database
                            if session_id:
                                self.store_discovered_service(session_id, host, service_entry, port_info)
                
                scan_results[host] = host_results
                
                # Update host info in database
                if session_id and host_results['os']:
                    self.update_host_os_info(session_id, host, host_results['os'])
            
            logger.info(f"Port scan completed for {target}")
            return scan_results
            
        except Exception as e:
            logger.error(f"Error during port scan: {e}")
            return {}

    async def async_port_scan(self, targets, ports='1-1000', scan_type='syn', session_id=None, max_concurrent=5):
        """Perform asynchronous port scans on multiple targets"""
        logger.info(f"Starting async port scan on {len(targets)} targets")
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_target(target):
            async with semaphore:
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    result = await loop.run_in_executor(
                        executor, 
                        self.port_scan, 
                        target, 
                        ports, 
                        scan_type, 
                        session_id
                    )
                return result
        
        # Create tasks for all targets
        tasks = [scan_target(target) for target in targets]
        
        # Execute scans concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        combined_results = {}
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Error scanning {targets[i]}: {result}")
            else:
                combined_results.update(result)
        
        logger.info(f"Async port scan completed. Scanned {len(combined_results)} hosts")
        return combined_results

    def service_enumeration(self, target, ports=None, session_id=None):
        """Perform detailed service enumeration"""
        logger.info(f"Starting service enumeration for {target}")
        
        if ports:
            port_arg = ','.join(map(str, ports))
        else:
            port_arg = '1-65535'
        
        try:
            # Comprehensive service scan
            self.nm.scan(
                hosts=target,
                ports=port_arg,
                arguments='-sV -sC --script=banner,http-title,ssh-hostkey,ssl-cert'
            )
            
            enumeration_results = {}
            
            for host in self.nm.all_hosts():
                host_services = []
                
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        
                        if port_info['state'] == 'open':
                            service_detail = {
                                'port': port,
                                'protocol': protocol,
                                'service': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'scripts': {}
                            }
                            
                            # Extract script results
                            if 'script' in port_info:
                                service_detail['scripts'] = port_info['script']
                            
                            host_services.append(service_detail)
                
                enumeration_results[host] = host_services
            
            logger.info(f"Service enumeration completed for {target}")
            return enumeration_results
            
        except Exception as e:
            logger.error(f"Error during service enumeration: {e}")
            return {}

    def store_discovered_host(self, session_id, host_info):
        """Store discovered host in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO discovered_hosts 
            (session_id, ip_address, hostname, mac_address, vendor, status, discovery_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            host_info['ip'],
            host_info.get('hostname'),
            host_info.get('mac'),
            host_info.get('vendor'),
            host_info['status'],
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()

    def store_discovered_service(self, session_id, ip_address, service_info, port_info):
        """Store discovered service in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO discovered_services 
            (session_id, ip_address, port, protocol, service_name, service_version, 
             service_product, service_extrainfo, state, reason, discovery_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            ip_address,
            service_info['port'],
            service_info['protocol'],
            service_info.get('service', ''),
            service_info.get('version', ''),
            service_info.get('product', ''),
            port_info.get('extrainfo', ''),
            port_info['state'],
            port_info.get('reason', ''),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()

    def update_host_os_info(self, session_id, ip_address, os_info):
        """Update host OS information in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE discovered_hosts 
            SET os_name = ?, os_accuracy = ?
            WHERE session_id = ? AND ip_address = ?
        ''', (
            os_info['name'],
            os_info['accuracy'],
            session_id,
            ip_address
        ))
        
        conn.commit()
        conn.close()

    def create_scan_session(self, target_range, scan_type):
        """Create a new scan session"""
        session_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_sessions 
            (session_id, start_time, target_range, scan_type, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            session_id,
            datetime.now().isoformat(),
            target_range,
            scan_type,
            'running'
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created scan session: {session_id}")
        return session_id

    def complete_scan_session(self, session_id):
        """Mark scan session as completed"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE scan_sessions 
            SET end_time = ?, status = ?
            WHERE session_id = ?
        ''', (
            datetime.now().isoformat(),
            'completed',
            session_id
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Completed scan session: {session_id}")

    def get_scan_results(self, session_id):
        """Retrieve scan results from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get session info
        cursor.execute('SELECT * FROM scan_sessions WHERE session_id = ?', (session_id,))
        session_info = cursor.fetchone()
        
        # Get discovered hosts
        cursor.execute('SELECT * FROM discovered_hosts WHERE session_id = ?', (session_id,))
        hosts = cursor.fetchall()
        
        # Get discovered services
        cursor.execute('SELECT * FROM discovered_services WHERE session_id = ?', (session_id,))
        services = cursor.fetchall()
        
        conn.close()
        
        return {
            'session_info': session_info,
            'hosts': hosts,
            'services': services
        }

if __name__ == '__main__':
    # Example usage
    discovery = NetworkDiscovery()
    
    # Create scan session
    session_id = discovery.create_scan_session('192.168.1.0/24', 'comprehensive')
    
    try:
        # Discover live hosts
        live_hosts = discovery.ping_sweep('192.168.1.0/24', session_id)
        print(f"Found {len(live_hosts)} live hosts")
        
        # Scan ports on discovered hosts
        if live_hosts:
            target_ips = [host['ip'] for host in live_hosts[:5]]  # Limit to first 5 hosts
            
            # Run async port scan
            import asyncio
            results = asyncio.run(discovery.async_port_scan(target_ips, '1-1000', 'syn', session_id))
            
            print(f"Port scan completed for {len(results)} hosts")
            
            # Print summary
            for ip, host_data in results.items():
                print(f"\nHost: {ip} ({host_data.get('hostname', 'Unknown')})")
                print(f"Status: {host_data['status']}")
                print(f"Open services: {len(host_data['services'])}")
                
                for service in host_data['services'][:5]:  # Show first 5 services
                    print(f"  - {service['port']}/{service['protocol']}: {service['service']}")
        
        # Complete session
        discovery.complete_scan_session(session_id)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        discovery.complete_scan_session(session_id)
    except Exception as e:
        print(f"Error during scan: {e}")
        discovery.complete_scan_session(session_id)
