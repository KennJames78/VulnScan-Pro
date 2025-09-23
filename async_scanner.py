#!/usr/bin/env python3
"""
VulnScan-Pro: Asynchronous Scanning Architecture
High-performance concurrent multi-target vulnerability assessment
"""

import asyncio
import aiohttp
import time
import json
import sqlite3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import List, Dict, Optional, Callable
import logging
from dataclasses import dataclass
from enum import Enum
import queue
import threading
from network_discovery import NetworkDiscovery
from cve_integration import CVEIntegration

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class ScanTask:
    task_id: str
    target: str
    scan_type: str
    priority: int
    created_at: datetime
    status: ScanStatus = ScanStatus.PENDING
    progress: float = 0.0
    result: Optional[Dict] = None
    error: Optional[str] = None

class AsyncVulnerabilityScanner:
    def __init__(self, max_concurrent_scans=10, max_workers=20, db_path='vulnscan_results.db'):
        self.max_concurrent_scans = max_concurrent_scans
        self.max_workers = max_workers
        self.db_path = db_path
        
        # Core components
        self.network_discovery = NetworkDiscovery(db_path)
        self.cve_integration = CVEIntegration(db_path)
        
        # Async components
        self.scan_queue = asyncio.Queue()
        self.active_scans = {}
        self.scan_results = {}
        self.scan_semaphore = asyncio.Semaphore(max_concurrent_scans)
        
        # Thread pools for CPU-intensive tasks
        self.thread_executor = ThreadPoolExecutor(max_workers=max_workers)
        self.process_executor = ProcessPoolExecutor(max_workers=4)
        
        # Progress tracking
        self.progress_callbacks = {}
        self.scan_statistics = {
            'total_scans': 0,
            'completed_scans': 0,
            'failed_scans': 0,
            'active_scans': 0,
            'average_scan_time': 0.0
        }
        
        # Performance optimization
        self.scan_cache = {}
        self.rate_limiter = asyncio.Semaphore(50)  # Global rate limiting
        
    async def add_scan_task(self, target: str, scan_type: str = 'comprehensive', 
                           priority: int = 1) -> str:
        """Add a new scan task to the queue"""
        task_id = f"scan_{int(time.time() * 1000)}_{len(self.active_scans)}"
        
        task = ScanTask(
            task_id=task_id,
            target=target,
            scan_type=scan_type,
            priority=priority,
            created_at=datetime.now()
        )
        
        await self.scan_queue.put(task)
        self.active_scans[task_id] = task
        
        logger.info(f"Added scan task {task_id} for target {target}")
        return task_id

    async def start_scan_worker(self):
        """Start the main scan worker loop"""
        logger.info("Starting async scan worker")
        
        while True:
            try:
                # Get next task from queue
                task = await self.scan_queue.get()
                
                # Process the task
                await self.process_scan_task(task)
                
                # Mark task as done
                self.scan_queue.task_done()
                
            except asyncio.CancelledError:
                logger.info("Scan worker cancelled")
                break
            except Exception as e:
                logger.error(f"Error in scan worker: {e}")
                await asyncio.sleep(1)

    async def process_scan_task(self, task: ScanTask):
        """Process a single scan task"""
        async with self.scan_semaphore:
            task.status = ScanStatus.RUNNING
            start_time = time.time()
            
            try:
                logger.info(f"Starting scan {task.task_id} for {task.target}")
                
                # Update statistics
                self.scan_statistics['active_scans'] += 1
                
                # Perform the scan based on type
                if task.scan_type == 'ping_sweep':
                    result = await self.async_ping_sweep(task)
                elif task.scan_type == 'port_scan':
                    result = await self.async_port_scan(task)
                elif task.scan_type == 'vulnerability_scan':
                    result = await self.async_vulnerability_scan(task)
                elif task.scan_type == 'comprehensive':
                    result = await self.async_comprehensive_scan(task)
                else:
                    raise ValueError(f"Unknown scan type: {task.scan_type}")
                
                # Store results
                task.result = result
                task.status = ScanStatus.COMPLETED
                task.progress = 100.0
                
                # Update statistics
                scan_time = time.time() - start_time
                self.update_scan_statistics(scan_time, success=True)
                
                logger.info(f"Completed scan {task.task_id} in {scan_time:.2f}s")
                
            except Exception as e:
                task.error = str(e)
                task.status = ScanStatus.FAILED
                self.update_scan_statistics(time.time() - start_time, success=False)
                logger.error(f"Scan {task.task_id} failed: {e}")
            
            finally:
                self.scan_statistics['active_scans'] -= 1
                
                # Notify progress callbacks
                if task.task_id in self.progress_callbacks:
                    callback = self.progress_callbacks[task.task_id]
                    await callback(task)

    async def async_ping_sweep(self, task: ScanTask) -> Dict:
        """Asynchronous ping sweep"""
        loop = asyncio.get_event_loop()
        
        # Create session for this scan
        session_id = self.network_discovery.create_scan_session(task.target, 'ping_sweep')
        
        # Run ping sweep in thread pool
        result = await loop.run_in_executor(
            self.thread_executor,
            self.network_discovery.ping_sweep,
            task.target,
            session_id
        )
        
        # Complete session
        self.network_discovery.complete_scan_session(session_id)
        
        return {
            'session_id': session_id,
            'live_hosts': result,
            'host_count': len(result)
        }

    async def async_port_scan(self, task: ScanTask) -> Dict:
        """Asynchronous port scan"""
        loop = asyncio.get_event_loop()
        
        # Create session
        session_id = self.network_discovery.create_scan_session(task.target, 'port_scan')
        
        # Determine if target is single host or range
        if '/' in task.target or '-' in task.target:
            # Multiple targets - use async scanning
            # First discover live hosts
            live_hosts = await loop.run_in_executor(
                self.thread_executor,
                self.network_discovery.ping_sweep,
                task.target,
                session_id
            )
            
            if live_hosts:
                target_ips = [host['ip'] for host in live_hosts]
                result = await self.network_discovery.async_port_scan(
                    target_ips, '1-1000', 'syn', session_id, max_concurrent=5
                )
            else:
                result = {}
        else:
            # Single target
            result = await loop.run_in_executor(
                self.thread_executor,
                self.network_discovery.port_scan,
                task.target,
                '1-1000',
                'syn',
                session_id
            )
        
        self.network_discovery.complete_scan_session(session_id)
        
        return {
            'session_id': session_id,
            'scan_results': result,
            'hosts_scanned': len(result)
        }

    async def async_vulnerability_scan(self, task: ScanTask) -> Dict:
        """Asynchronous vulnerability scan"""
        # First perform port scan to discover services
        port_scan_task = ScanTask(
            task_id=f"{task.task_id}_portscan",
            target=task.target,
            scan_type='port_scan',
            priority=task.priority,
            created_at=datetime.now()
        )
        
        port_results = await self.async_port_scan(port_scan_task)
        task.progress = 30.0
        
        # Extract services from port scan results
        services = []
        for ip, host_data in port_results['scan_results'].items():
            for service in host_data.get('services', []):
                service['ip_address'] = ip
                services.append(service)
        
        task.progress = 50.0
        
        # Perform vulnerability matching
        vuln_results = await self.cve_integration.async_vulnerability_scan(
            services, port_results['session_id']
        )
        
        task.progress = 90.0
        
        # Get vulnerability summary
        summary = self.cve_integration.get_vulnerability_summary(port_results['session_id'])
        
        return {
            'session_id': port_results['session_id'],
            'services_scanned': len(services),
            'vulnerabilities': vuln_results,
            'summary': summary
        }

    async def async_comprehensive_scan(self, task: ScanTask) -> Dict:
        """Comprehensive asynchronous scan"""
        results = {
            'scan_type': 'comprehensive',
            'target': task.target,
            'start_time': datetime.now().isoformat()
        }
        
        try:
            # Phase 1: Host Discovery
            logger.info(f"Phase 1: Host discovery for {task.target}")
            ping_task = ScanTask(
                task_id=f"{task.task_id}_ping",
                target=task.target,
                scan_type='ping_sweep',
                priority=task.priority,
                created_at=datetime.now()
            )
            
            ping_results = await self.async_ping_sweep(ping_task)
            results['host_discovery'] = ping_results
            task.progress = 20.0
            
            if not ping_results['live_hosts']:
                logger.warning(f"No live hosts found for {task.target}")
                return results
            
            # Phase 2: Port Scanning
            logger.info(f"Phase 2: Port scanning {len(ping_results['live_hosts'])} hosts")
            target_ips = [host['ip'] for host in ping_results['live_hosts']]
            
            # Use the same session ID for consistency
            session_id = ping_results['session_id']
            
            port_results = await self.network_discovery.async_port_scan(
                target_ips, '1-65535', 'comprehensive', session_id, max_concurrent=3
            )
            
            results['port_scan'] = {
                'session_id': session_id,
                'scan_results': port_results,
                'hosts_scanned': len(port_results)
            }
            task.progress = 50.0
            
            # Phase 3: Service Enumeration
            logger.info(f"Phase 3: Service enumeration")
            services = []
            for ip, host_data in port_results.items():
                for service in host_data.get('services', []):
                    service['ip_address'] = ip
                    services.append(service)
            
            results['services'] = services
            task.progress = 70.0
            
            # Phase 4: Vulnerability Assessment
            logger.info(f"Phase 4: Vulnerability assessment for {len(services)} services")
            if services:
                vuln_results = await self.cve_integration.async_vulnerability_scan(
                    services, session_id
                )
                
                summary = self.cve_integration.get_vulnerability_summary(session_id)
                
                results['vulnerabilities'] = vuln_results
                results['vulnerability_summary'] = summary
            
            task.progress = 90.0
            
            # Phase 5: Risk Assessment
            logger.info(f"Phase 5: Risk assessment")
            risk_assessment = self.calculate_risk_score(results)
            results['risk_assessment'] = risk_assessment
            
            # Complete the session
            self.network_discovery.complete_scan_session(session_id)
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            results['status'] = 'failed'
            results['end_time'] = datetime.now().isoformat()
            raise

    def calculate_risk_score(self, scan_results: Dict) -> Dict:
        """Calculate overall risk score for scan results"""
        risk_score = 0.0
        risk_factors = []
        
        # Host exposure factor
        live_hosts = len(scan_results.get('host_discovery', {}).get('live_hosts', []))
        if live_hosts > 10:
            risk_score += 2.0
            risk_factors.append(f"High number of exposed hosts ({live_hosts})")
        elif live_hosts > 5:
            risk_score += 1.0
            risk_factors.append(f"Moderate number of exposed hosts ({live_hosts})")
        
        # Service exposure factor
        services = scan_results.get('services', [])
        open_services = len(services)
        if open_services > 50:
            risk_score += 3.0
            risk_factors.append(f"High number of open services ({open_services})")
        elif open_services > 20:
            risk_score += 2.0
            risk_factors.append(f"Moderate number of open services ({open_services})")
        
        # Vulnerability factor
        vuln_summary = scan_results.get('vulnerability_summary', {})
        severity_counts = vuln_summary.get('severity_counts', {})
        
        critical_vulns = severity_counts.get('CRITICAL', 0)
        high_vulns = severity_counts.get('HIGH', 0)
        medium_vulns = severity_counts.get('MEDIUM', 0)
        
        risk_score += critical_vulns * 5.0
        risk_score += high_vulns * 3.0
        risk_score += medium_vulns * 1.0
        
        if critical_vulns > 0:
            risk_factors.append(f"{critical_vulns} critical vulnerabilities found")
        if high_vulns > 0:
            risk_factors.append(f"{high_vulns} high-severity vulnerabilities found")
        
        # Determine risk level
        if risk_score >= 20:
            risk_level = 'CRITICAL'
        elif risk_score >= 10:
            risk_level = 'HIGH'
        elif risk_score >= 5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendations': self.generate_recommendations(scan_results, risk_level)
        }

    def generate_recommendations(self, scan_results: Dict, risk_level: str) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Host-based recommendations
        live_hosts = len(scan_results.get('host_discovery', {}).get('live_hosts', []))
        if live_hosts > 10:
            recommendations.append("Consider network segmentation to reduce attack surface")
        
        # Service-based recommendations
        services = scan_results.get('services', [])
        service_ports = [s.get('port') for s in services]
        
        if 22 in service_ports:
            recommendations.append("Secure SSH access with key-based authentication and disable root login")
        if 21 in service_ports:
            recommendations.append("Replace FTP with secure alternatives like SFTP or FTPS")
        if 23 in service_ports:
            recommendations.append("Disable Telnet and use SSH instead")
        if 3389 in service_ports:
            recommendations.append("Secure RDP with strong authentication and network-level authentication")
        
        # Vulnerability-based recommendations
        vuln_summary = scan_results.get('vulnerability_summary', {})
        severity_counts = vuln_summary.get('severity_counts', {})
        
        if severity_counts.get('CRITICAL', 0) > 0:
            recommendations.append("Immediately patch critical vulnerabilities")
        if severity_counts.get('HIGH', 0) > 0:
            recommendations.append("Prioritize patching of high-severity vulnerabilities")
        
        # Risk-level specific recommendations
        if risk_level == 'CRITICAL':
            recommendations.extend([
                "Implement emergency incident response procedures",
                "Consider taking affected systems offline until patched",
                "Conduct immediate security audit"
            ])
        elif risk_level == 'HIGH':
            recommendations.extend([
                "Implement additional monitoring and alerting",
                "Review and update security policies",
                "Consider penetration testing"
            ])
        
        return recommendations

    def update_scan_statistics(self, scan_time: float, success: bool):
        """Update scan performance statistics"""
        self.scan_statistics['total_scans'] += 1
        
        if success:
            self.scan_statistics['completed_scans'] += 1
        else:
            self.scan_statistics['failed_scans'] += 1
        
        # Update average scan time
        current_avg = self.scan_statistics['average_scan_time']
        total_scans = self.scan_statistics['total_scans']
        
        self.scan_statistics['average_scan_time'] = \
            ((current_avg * (total_scans - 1)) + scan_time) / total_scans

    async def get_scan_status(self, task_id: str) -> Optional[Dict]:
        """Get status of a specific scan task"""
        if task_id in self.active_scans:
            task = self.active_scans[task_id]
            return {
                'task_id': task.task_id,
                'target': task.target,
                'scan_type': task.scan_type,
                'status': task.status.value,
                'progress': task.progress,
                'created_at': task.created_at.isoformat(),
                'error': task.error
            }
        return None

    async def cancel_scan(self, task_id: str) -> bool:
        """Cancel a running scan"""
        if task_id in self.active_scans:
            task = self.active_scans[task_id]
            if task.status == ScanStatus.RUNNING:
                task.status = ScanStatus.CANCELLED
                logger.info(f"Cancelled scan {task_id}")
                return True
        return False

    def get_performance_metrics(self) -> Dict:
        """Get scanner performance metrics"""
        return {
            'statistics': self.scan_statistics.copy(),
            'queue_size': self.scan_queue.qsize(),
            'active_scans': len([t for t in self.active_scans.values() 
                               if t.status == ScanStatus.RUNNING]),
            'cache_size': len(self.scan_cache)
        }

    async def cleanup_completed_scans(self, max_age_hours: int = 24):
        """Clean up old completed scan tasks"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        to_remove = []
        for task_id, task in self.active_scans.items():
            if (task.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED] 
                and task.created_at < cutoff_time):
                to_remove.append(task_id)
        
        for task_id in to_remove:
            del self.active_scans[task_id]
            if task_id in self.progress_callbacks:
                del self.progress_callbacks[task_id]
        
        logger.info(f"Cleaned up {len(to_remove)} old scan tasks")

    async def shutdown(self):
        """Gracefully shutdown the scanner"""
        logger.info("Shutting down async vulnerability scanner")
        
        # Cancel all pending tasks
        for task in self.active_scans.values():
            if task.status == ScanStatus.RUNNING:
                task.status = ScanStatus.CANCELLED
        
        # Shutdown executors
        self.thread_executor.shutdown(wait=True)
        self.process_executor.shutdown(wait=True)
        
        logger.info("Async vulnerability scanner shutdown complete")

if __name__ == '__main__':
    async def main():
        # Example usage
        scanner = AsyncVulnerabilityScanner(max_concurrent_scans=5)
        
        # Start the scan worker
        worker_task = asyncio.create_task(scanner.start_scan_worker())
        
        try:
            # Add some scan tasks
            task1 = await scanner.add_scan_task('192.168.1.0/24', 'comprehensive')
            task2 = await scanner.add_scan_task('10.0.0.1', 'vulnerability_scan')
            
            print(f"Started scans: {task1}, {task2}")
            
            # Monitor progress
            while True:
                status1 = await scanner.get_scan_status(task1)
                status2 = await scanner.get_scan_status(task2)
                
                print(f"Task 1: {status1['status']} ({status1['progress']:.1f}%)")
                print(f"Task 2: {status2['status']} ({status2['progress']:.1f}%)")
                
                if (status1['status'] in ['completed', 'failed'] and 
                    status2['status'] in ['completed', 'failed']):
                    break
                
                await asyncio.sleep(5)
            
            # Print results
            print("\nScan Results:")
            for task_id in [task1, task2]:
                task = scanner.active_scans[task_id]
                if task.result:
                    print(f"\nTask {task_id}:")
                    if 'vulnerability_summary' in task.result:
                        summary = task.result['vulnerability_summary']
                        print(f"  Total vulnerabilities: {summary['total_vulnerabilities']}")
                        print(f"  Severity breakdown: {summary['severity_counts']}")
        
        except KeyboardInterrupt:
            print("\nShutting down...")
        
        finally:
            worker_task.cancel()
            await scanner.shutdown()
    
    # Run the example
    asyncio.run(main())
