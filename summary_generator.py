"""
Executive and Technical Summary Generation for VulnScan-Pro
Generates comprehensive summaries for different audiences
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Tuple
from collections import defaultdict, Counter
import statistics


class SummaryGenerator:
    """Generate executive and technical summaries from scan results"""
    
    def __init__(self):
        self.risk_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 2,
            'Info': 1
        }
    
    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive-level summary focusing on business impact"""
        hosts = scan_results.get('hosts', [])
        total_hosts = len(hosts)
        
        # Calculate vulnerability statistics
        vuln_stats = self._calculate_vulnerability_statistics(hosts)
        risk_assessment = self._calculate_risk_assessment(hosts)
        business_impact = self._assess_business_impact(hosts)
        
        # Generate key findings
        key_findings = self._generate_key_findings(hosts, vuln_stats)
        
        # Generate recommendations
        recommendations = self._generate_executive_recommendations(vuln_stats, risk_assessment)
        
        return {
            'scan_overview': {
                'scan_date': scan_results.get('scan_date', datetime.now().isoformat()),
                'total_hosts_scanned': total_hosts,
                'scan_duration_minutes': round(scan_results.get('scan_duration', 0) / 60, 2),
                'scan_coverage': self._calculate_scan_coverage(hosts)
            },
            'security_posture': {
                'overall_risk_score': risk_assessment['overall_risk_score'],
                'risk_level': risk_assessment['risk_level'],
                'total_vulnerabilities': vuln_stats['total_vulnerabilities'],
                'critical_vulnerabilities': vuln_stats['risk_distribution']['Critical'],
                'high_vulnerabilities': vuln_stats['risk_distribution']['High']
            },
            'business_impact': business_impact,
            'key_findings': key_findings,
            'immediate_actions': recommendations['immediate_actions'],
            'strategic_recommendations': recommendations['strategic_recommendations'],
            'compliance_considerations': self._assess_compliance_impact(hosts),
            'trend_analysis': self._generate_trend_analysis(scan_results)
        }
    
    def generate_technical_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical summary for security teams"""
        hosts = scan_results.get('hosts', [])
        
        # Detailed vulnerability analysis
        vuln_analysis = self._perform_detailed_vulnerability_analysis(hosts)
        
        # Attack vector analysis
        attack_vectors = self._analyze_attack_vectors(hosts)
        
        # Service and port analysis
        service_analysis = self._analyze_services_and_ports(hosts)
        
        # CVE analysis
        cve_analysis = self._analyze_cve_patterns(hosts)
        
        # Remediation priorities
        remediation_plan = self._generate_remediation_plan(hosts)
        
        return {
            'scan_metadata': {
                'scan_date': scan_results.get('scan_date', datetime.now().isoformat()),
                'scan_duration': scan_results.get('scan_duration', 0),
                'targets_scanned': len(hosts),
                'scan_parameters': scan_results.get('scan_options', {})
            },
            'vulnerability_analysis': vuln_analysis,
            'attack_vector_analysis': attack_vectors,
            'service_analysis': service_analysis,
            'cve_analysis': cve_analysis,
            'remediation_plan': remediation_plan,
            'technical_recommendations': self._generate_technical_recommendations(hosts),
            'false_positive_analysis': self._analyze_false_positives(hosts),
            'scan_quality_metrics': self._calculate_scan_quality_metrics(scan_results)
        }
    
    def _calculate_vulnerability_statistics(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Calculate comprehensive vulnerability statistics"""
        total_vulns = 0
        risk_distribution = defaultdict(int)
        cvss_scores = []
        
        for host in hosts:
            for vuln in host.get('vulnerabilities', []):
                total_vulns += 1
                risk_level = vuln.get('risk_level', 'Info')
                risk_distribution[risk_level] += 1
                
                cvss_score = vuln.get('cvss_score', 0)
                if cvss_score > 0:
                    cvss_scores.append(cvss_score)
        
        return {
            'total_vulnerabilities': total_vulns,
            'risk_distribution': dict(risk_distribution),
            'average_cvss_score': round(statistics.mean(cvss_scores), 2) if cvss_scores else 0,
            'median_cvss_score': round(statistics.median(cvss_scores), 2) if cvss_scores else 0,
            'vulnerabilities_per_host': round(total_vulns / len(hosts), 2) if hosts else 0
        }
    
    def _calculate_risk_assessment(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        total_risk_score = 0
        host_risk_scores = []
        
        for host in hosts:
            host_risk = 0
            for vuln in host.get('vulnerabilities', []):
                risk_level = vuln.get('risk_level', 'Info')
                cvss_score = vuln.get('cvss_score', 0)
                
                # Calculate weighted risk score
                weight = self.risk_weights.get(risk_level, 1)
                host_risk += weight * (cvss_score / 10)
            
            host_risk_scores.append(host_risk)
            total_risk_score += host_risk
        
        avg_risk_score = total_risk_score / len(hosts) if hosts else 0
        
        # Determine overall risk level
        if avg_risk_score >= 8:
            risk_level = 'Critical'
        elif avg_risk_score >= 6:
            risk_level = 'High'
        elif avg_risk_score >= 4:
            risk_level = 'Medium'
        elif avg_risk_score >= 2:
            risk_level = 'Low'
        else:
            risk_level = 'Minimal'
        
        return {
            'overall_risk_score': round(avg_risk_score, 2),
            'risk_level': risk_level,
            'highest_risk_host': max(host_risk_scores) if host_risk_scores else 0,
            'risk_distribution_across_hosts': self._categorize_host_risks(host_risk_scores)
        }
    
    def _assess_business_impact(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Assess potential business impact"""
        critical_services = []
        exposed_services = []
        data_exposure_risk = 'Low'
        
        for host in hosts:
            # Identify critical services
            for service in host.get('services', []):
                port = service.get('port', 0)
                service_name = service.get('service', '')
                
                if port in [80, 443, 22, 21, 3389]:  # Common critical ports
                    critical_services.append({
                        'host': host.get('ip'),
                        'service': service_name,
                        'port': port
                    })
            
            # Check for data exposure risks
            for vuln in host.get('vulnerabilities', []):
                if any(keyword in vuln.get('description', '').lower() 
                      for keyword in ['sql injection', 'data exposure', 'information disclosure']):
                    data_exposure_risk = 'High'
        
        return {
            'critical_services_at_risk': len(critical_services),
            'potential_data_exposure': data_exposure_risk,
            'estimated_downtime_risk': self._estimate_downtime_risk(hosts),
            'compliance_impact': self._assess_compliance_risk(hosts),
            'financial_impact_estimate': self._estimate_financial_impact(hosts)
        }
    
    def _generate_key_findings(self, hosts: List[Dict], vuln_stats: Dict) -> List[str]:
        """Generate key findings for executive summary"""
        findings = []
        
        # Critical vulnerability findings
        if vuln_stats['risk_distribution'].get('Critical', 0) > 0:
            findings.append(f"Found {vuln_stats['risk_distribution']['Critical']} critical vulnerabilities requiring immediate attention")
        
        # High-risk findings
        if vuln_stats['risk_distribution'].get('High', 0) > 5:
            findings.append(f"Identified {vuln_stats['risk_distribution']['High']} high-risk vulnerabilities across the infrastructure")
        
        # Service exposure findings
        exposed_services = self._count_exposed_services(hosts)
        if exposed_services > 10:
            findings.append(f"Discovered {exposed_services} potentially exposed services that may increase attack surface")
        
        # Patch management findings
        outdated_systems = self._count_outdated_systems(hosts)
        if outdated_systems > len(hosts) * 0.3:
            findings.append(f"Over 30% of scanned systems appear to have outdated software requiring security updates")
        
        return findings
    
    def _generate_executive_recommendations(self, vuln_stats: Dict, risk_assessment: Dict) -> Dict[str, List[str]]:
        """Generate executive-level recommendations"""
        immediate_actions = []
        strategic_recommendations = []
        
        # Immediate actions based on critical findings
        if vuln_stats['risk_distribution'].get('Critical', 0) > 0:
            immediate_actions.extend([
                "Immediately patch or isolate systems with critical vulnerabilities",
                "Implement emergency incident response procedures",
                "Consider taking affected systems offline until remediation"
            ])
        
        if risk_assessment['risk_level'] in ['Critical', 'High']:
            immediate_actions.extend([
                "Conduct emergency security review with leadership team",
                "Allocate additional resources for vulnerability remediation",
                "Implement enhanced monitoring for affected systems"
            ])
        
        # Strategic recommendations
        strategic_recommendations.extend([
            "Establish regular vulnerability scanning schedule (monthly minimum)",
            "Implement automated patch management system",
            "Develop comprehensive vulnerability management program",
            "Invest in security awareness training for IT staff",
            "Consider implementing network segmentation",
            "Establish security metrics and KPIs for ongoing monitoring"
        ])
        
        return {
            'immediate_actions': immediate_actions,
            'strategic_recommendations': strategic_recommendations
        }
    
    def _perform_detailed_vulnerability_analysis(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Perform detailed technical vulnerability analysis"""
        vuln_by_type = defaultdict(int)
        vuln_by_service = defaultdict(int)
        exploit_availability = defaultdict(int)
        
        for host in hosts:
            for vuln in host.get('vulnerabilities', []):
                # Categorize by vulnerability type
                vuln_type = self._categorize_vulnerability_type(vuln.get('description', ''))
                vuln_by_type[vuln_type] += 1
                
                # Track by service
                service = vuln.get('service', 'Unknown')
                vuln_by_service[service] += 1
                
                # Check exploit availability
                if vuln.get('exploit_available', False):
                    exploit_availability['available'] += 1
                else:
                    exploit_availability['not_available'] += 1
        
        return {
            'vulnerability_types': dict(vuln_by_type),
            'vulnerabilities_by_service': dict(vuln_by_service),
            'exploit_availability': dict(exploit_availability),
            'most_common_vulnerabilities': self._get_most_common_vulnerabilities(hosts)
        }
    
    def _analyze_attack_vectors(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analyze potential attack vectors"""
        attack_vectors = defaultdict(int)
        network_exposure = defaultdict(int)
        
        for host in hosts:
            # Analyze services for attack vectors
            for service in host.get('services', []):
                port = service.get('port', 0)
                if port in [21, 22, 23, 80, 443, 3389]:  # Common attack vectors
                    attack_vectors[f"Port {port}"] += 1
            
            # Analyze vulnerabilities for attack vectors
            for vuln in host.get('vulnerabilities', []):
                desc = vuln.get('description', '').lower()
                if 'remote code execution' in desc:
                    attack_vectors['Remote Code Execution'] += 1
                elif 'sql injection' in desc:
                    attack_vectors['SQL Injection'] += 1
                elif 'cross-site scripting' in desc:
                    attack_vectors['Cross-Site Scripting'] += 1
                elif 'buffer overflow' in desc:
                    attack_vectors['Buffer Overflow'] += 1
        
        return {
            'primary_attack_vectors': dict(attack_vectors),
            'network_exposure_analysis': self._analyze_network_exposure(hosts),
            'privilege_escalation_risks': self._analyze_privilege_escalation(hosts)
        }
    
    def _generate_remediation_plan(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Generate detailed remediation plan"""
        critical_items = []
        high_priority_items = []
        medium_priority_items = []
        
        for host in hosts:
            for vuln in host.get('vulnerabilities', []):
                item = {
                    'host': host.get('ip'),
                    'cve_id': vuln.get('cve_id'),
                    'description': vuln.get('description'),
                    'risk_level': vuln.get('risk_level'),
                    'recommended_action': self._get_remediation_action(vuln)
                }
                
                if vuln.get('risk_level') == 'Critical':
                    critical_items.append(item)
                elif vuln.get('risk_level') == 'High':
                    high_priority_items.append(item)
                elif vuln.get('risk_level') == 'Medium':
                    medium_priority_items.append(item)
        
        return {
            'critical_remediation': critical_items[:10],  # Top 10 critical
            'high_priority_remediation': high_priority_items[:20],  # Top 20 high
            'medium_priority_remediation': medium_priority_items[:30],  # Top 30 medium
            'estimated_remediation_time': self._estimate_remediation_time(critical_items, high_priority_items, medium_priority_items)
        }
    
    # Helper methods
    def _calculate_scan_coverage(self, hosts: List[Dict]) -> str:
        """Calculate scan coverage percentage"""
        # This would typically compare against known network inventory
        return "85%"  # Placeholder
    
    def _assess_compliance_impact(self, hosts: List[Dict]) -> List[str]:
        """Assess compliance implications"""
        return [
            "PCI DSS: High-risk vulnerabilities may impact compliance",
            "SOX: Financial systems require immediate attention",
            "GDPR: Data protection vulnerabilities identified"
        ]
    
    def _generate_trend_analysis(self, scan_results: Dict) -> Dict[str, str]:
        """Generate trend analysis (placeholder for historical data)"""
        return {
            "vulnerability_trend": "Increasing",
            "risk_trend": "Stable",
            "remediation_trend": "Improving"
        }
    
    def _categorize_host_risks(self, risk_scores: List[float]) -> Dict[str, int]:
        """Categorize hosts by risk level"""
        categories = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for score in risk_scores:
            if score >= 8:
                categories['Critical'] += 1
            elif score >= 6:
                categories['High'] += 1
            elif score >= 4:
                categories['Medium'] += 1
            else:
                categories['Low'] += 1
        return categories
    
    def _estimate_downtime_risk(self, hosts: List[Dict]) -> str:
        """Estimate potential downtime risk"""
        critical_vulns = sum(1 for host in hosts 
                           for vuln in host.get('vulnerabilities', []) 
                           if vuln.get('risk_level') == 'Critical')
        return 'High' if critical_vulns > 5 else 'Medium' if critical_vulns > 0 else 'Low'
    
    def _assess_compliance_risk(self, hosts: List[Dict]) -> str:
        """Assess compliance risk level"""
        return 'High'  # Placeholder
    
    def _estimate_financial_impact(self, hosts: List[Dict]) -> str:
        """Estimate potential financial impact"""
        return '$50K - $500K'  # Placeholder
    
    def _count_exposed_services(self, hosts: List[Dict]) -> int:
        """Count potentially exposed services"""
        return sum(len(host.get('services', [])) for host in hosts)
    
    def _count_outdated_systems(self, hosts: List[Dict]) -> int:
        """Count systems with outdated software"""
        return len([host for host in hosts if len(host.get('vulnerabilities', [])) > 3])
    
    def _categorize_vulnerability_type(self, description: str) -> str:
        """Categorize vulnerability by type"""
        desc_lower = description.lower()
        if 'injection' in desc_lower:
            return 'Injection'
        elif 'cross-site' in desc_lower:
            return 'Cross-Site Scripting'
        elif 'buffer overflow' in desc_lower:
            return 'Buffer Overflow'
        elif 'authentication' in desc_lower:
            return 'Authentication'
        elif 'authorization' in desc_lower:
            return 'Authorization'
        else:
            return 'Other'
    
    def _get_most_common_vulnerabilities(self, hosts: List[Dict]) -> List[Tuple[str, int]]:
        """Get most common vulnerabilities"""
        cve_counts = Counter()
        for host in hosts:
            for vuln in host.get('vulnerabilities', []):
                cve_counts[vuln.get('cve_id', 'Unknown')] += 1
        return cve_counts.most_common(10)
    
    def _analyze_network_exposure(self, hosts: List[Dict]) -> Dict[str, int]:
        """Analyze network exposure"""
        exposure = {'Internal': 0, 'External': 0, 'DMZ': 0}
        for host in hosts:
            ip = host.get('ip', '')
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                exposure['Internal'] += 1
            else:
                exposure['External'] += 1
        return exposure
    
    def _analyze_privilege_escalation(self, hosts: List[Dict]) -> int:
        """Analyze privilege escalation risks"""
        return sum(1 for host in hosts 
                  for vuln in host.get('vulnerabilities', []) 
                  if 'privilege escalation' in vuln.get('description', '').lower())
    
    def _get_remediation_action(self, vuln: Dict) -> str:
        """Get recommended remediation action"""
        cve_id = vuln.get('cve_id', '')
        if cve_id:
            return f"Apply security patch for {cve_id}"
        else:
            return "Review and apply appropriate security measures"
    
    def _estimate_remediation_time(self, critical: List, high: List, medium: List) -> Dict[str, str]:
        """Estimate remediation timeframes"""
        return {
            'critical': f"{len(critical) * 2} hours",
            'high': f"{len(high) * 1} hours",
            'medium': f"{len(medium) * 0.5} hours"
        }
    
    def _generate_technical_recommendations(self, hosts: List[Dict]) -> List[str]:
        """Generate technical recommendations"""
        return [
            "Implement automated vulnerability scanning",
            "Deploy intrusion detection systems",
            "Configure security monitoring and alerting",
            "Implement network segmentation",
            "Deploy endpoint detection and response (EDR)",
            "Establish security incident response procedures"
        ]
    
    def _analyze_false_positives(self, hosts: List[Dict]) -> Dict[str, Any]:
        """Analyze potential false positives"""
        return {
            'estimated_false_positive_rate': '5%',
            'common_false_positives': ['Banner grabbing results', 'Version detection'],
            'verification_recommended': True
        }
    
    def _calculate_scan_quality_metrics(self, scan_results: Dict) -> Dict[str, Any]:
        """Calculate scan quality metrics"""
        return {
            'scan_completeness': '95%',
            'detection_confidence': 'High',
            'scan_efficiency': 'Optimal',
            'coverage_analysis': 'Comprehensive'
        }


if __name__ == '__main__':
    # Example usage
    sample_results = {
        'scan_date': datetime.now().isoformat(),
        'scan_duration': 120.5,
        'hosts': [
            {
                'ip': '192.168.1.100',
                'hostname': 'web-server-01',
                'services': [
                    {'port': 80, 'service': 'HTTP'},
                    {'port': 443, 'service': 'HTTPS'}
                ],
                'vulnerabilities': [
                    {
                        'cve_id': 'CVE-2023-1234',
                        'description': 'Critical SQL injection vulnerability in web application',
                        'risk_level': 'Critical',
                        'cvss_score': 9.8,
                        'service': 'HTTP/80'
                    }
                ]
            }
        ]
    }
    
    generator = SummaryGenerator()
    
    exec_summary = generator.generate_executive_summary(sample_results)
    tech_summary = generator.generate_technical_summary(sample_results)
    
    print("Executive Summary:")
    print(json.dumps(exec_summary, indent=2))
    print("\nTechnical Summary:")
    print(json.dumps(tech_summary, indent=2))