"""
Multi-format reporting system for VulnScan-Pro
Generates PDF, JSON, and HTML reports with executive and technical summaries
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Template
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT


class ReportGenerator:
    """Generate comprehensive vulnerability assessment reports in multiple formats"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for PDF generation"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.darkred
        ))
    
    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from scan results"""
        total_hosts = len(scan_results.get('hosts', []))
        total_vulnerabilities = sum(len(host.get('vulnerabilities', [])) 
                                  for host in scan_results.get('hosts', []))
        
        # Risk level distribution
        risk_levels = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for host in scan_results.get('hosts', []):
            for vuln in host.get('vulnerabilities', []):
                risk = vuln.get('risk_level', 'Info')
                risk_levels[risk] = risk_levels.get(risk, 0) + 1
        
        # Top vulnerabilities
        vuln_counts = {}
        for host in scan_results.get('hosts', []):
            for vuln in host.get('vulnerabilities', []):
                cve_id = vuln.get('cve_id', 'Unknown')
                vuln_counts[cve_id] = vuln_counts.get(cve_id, 0) + 1
        
        top_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'scan_date': scan_results.get('scan_date', datetime.now().isoformat()),
            'total_hosts': total_hosts,
            'total_vulnerabilities': total_vulnerabilities,
            'risk_distribution': risk_levels,
            'top_vulnerabilities': top_vulns,
            'scan_duration': scan_results.get('scan_duration', 0),
            'recommendations': self._generate_recommendations(risk_levels)
        }
    
    def _generate_recommendations(self, risk_levels: Dict[str, int]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if risk_levels['Critical'] > 0:
            recommendations.append("Immediately patch all critical vulnerabilities")
            recommendations.append("Consider taking affected systems offline until patched")
        
        if risk_levels['High'] > 0:
            recommendations.append("Schedule high-priority vulnerability remediation within 48 hours")
        
        if risk_levels['Medium'] > 0:
            recommendations.append("Plan medium-priority patches within the next maintenance window")
        
        recommendations.extend([
            "Implement regular vulnerability scanning schedule",
            "Establish vulnerability management process",
            "Consider implementing network segmentation",
            "Review and update security policies"
        ])
        
        return recommendations
    
    def generate_json_report(self, scan_results: Dict[str, Any], filename: str = None) -> str:
        """Generate JSON format report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnscan_report_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Add executive summary to results
        executive_summary = self.generate_executive_summary(scan_results)
        report_data = {
            'executive_summary': executive_summary,
            'detailed_results': scan_results,
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_format': 'JSON',
                'tool_version': '1.0.0'
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return filepath
    
    def generate_html_report(self, scan_results: Dict[str, Any], filename: str = None) -> str:
        """Generate HTML format report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnscan_report_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        executive_summary = self.generate_executive_summary(scan_results)
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnScan-Pro Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #d32f2f; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
        .risk-critical { background-color: #ffebee; border-left: 4px solid #f44336; padding: 10px; }
        .risk-high { background-color: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; }
        .risk-medium { background-color: #fff8e1; border-left: 4px solid #ffc107; padding: 10px; }
        .risk-low { background-color: #e8f5e8; border-left: 4px solid #4caf50; padding: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #1976d2; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f5f5f5; font-weight: bold; }
        .vuln-table tr:hover { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VulnScan-Pro Vulnerability Assessment Report</h1>
            <p>Generated on: {{ executive_summary.scan_date }}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{{ executive_summary.total_hosts }}</div>
                    <div>Hosts Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ executive_summary.total_vulnerabilities }}</div>
                    <div>Vulnerabilities Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ executive_summary.scan_duration }}s</div>
                    <div>Scan Duration</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Risk Distribution</h2>
            {% for risk, count in executive_summary.risk_distribution.items() %}
            {% if count > 0 %}
            <div class="risk-{{ risk.lower() }}">
                <strong>{{ risk }}:</strong> {{ count }} vulnerabilities
            </div>
            {% endif %}
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Top Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Occurrences</th>
                    </tr>
                </thead>
                <tbody>
                    {% for cve, count in executive_summary.top_vulnerabilities %}
                    <tr>
                        <td>{{ cve }}</td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Detailed Findings</h2>
            {% for host in scan_results.hosts %}
            <h3>Host: {{ host.ip }} ({{ host.hostname or 'Unknown' }})</h3>
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Description</th>
                        <th>Risk Level</th>
                        <th>CVSS Score</th>
                        <th>Service</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in host.vulnerabilities %}
                    <tr>
                        <td>{{ vuln.cve_id }}</td>
                        <td>{{ vuln.description[:100] }}...</td>
                        <td><span class="risk-{{ vuln.risk_level.lower() }}">{{ vuln.risk_level }}</span></td>
                        <td>{{ vuln.cvss_score }}</td>
                        <td>{{ vuln.service }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                {% for recommendation in executive_summary.recommendations %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            executive_summary=executive_summary,
            scan_results=scan_results
        )
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return filepath
    
    def generate_pdf_report(self, scan_results: Dict[str, Any], filename: str = None) -> str:
        """Generate PDF format report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnscan_report_{timestamp}.pdf"
        
        filepath = os.path.join(self.output_dir, filename)
        executive_summary = self.generate_executive_summary(scan_results)
        
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        story = []
        
        # Title
        story.append(Paragraph("VulnScan-Pro Vulnerability Assessment Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 12))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Summary statistics
        summary_data = [
            ['Metric', 'Value'],
            ['Scan Date', executive_summary['scan_date']],
            ['Total Hosts Scanned', str(executive_summary['total_hosts'])],
            ['Total Vulnerabilities', str(executive_summary['total_vulnerabilities'])],
            ['Scan Duration', f"{executive_summary['scan_duration']} seconds"]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Risk Distribution
        story.append(Paragraph("Risk Distribution", self.styles['SectionHeader']))
        risk_data = [['Risk Level', 'Count']]
        for risk, count in executive_summary['risk_distribution'].items():
            if count > 0:
                risk_data.append([risk, str(count)])
        
        risk_table = Table(risk_data)
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 20))
        
        # Top Vulnerabilities
        story.append(Paragraph("Top Vulnerabilities", self.styles['SectionHeader']))
        vuln_data = [['CVE ID', 'Occurrences']]
        for cve, count in executive_summary['top_vulnerabilities']:
            vuln_data.append([cve, str(count)])
        
        vuln_table = Table(vuln_data)
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(vuln_table)
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        for i, recommendation in enumerate(executive_summary['recommendations'], 1):
            story.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
            story.append(Spacer(1, 6))
        
        doc.build(story)
        return filepath
    
    def generate_all_reports(self, scan_results: Dict[str, Any], base_filename: str = None) -> Dict[str, str]:
        """Generate all report formats"""
        if not base_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"vulnscan_report_{timestamp}"
        
        reports = {}
        reports['json'] = self.generate_json_report(scan_results, f"{base_filename}.json")
        reports['html'] = self.generate_html_report(scan_results, f"{base_filename}.html")
        reports['pdf'] = self.generate_pdf_report(scan_results, f"{base_filename}.pdf")
        
        return reports


if __name__ == "__main__":
    # Example usage
    sample_results = {
        'scan_date': datetime.now().isoformat(),
        'scan_duration': 45.2,
        'hosts': [
            {
                'ip': '192.168.1.100',
                'hostname': 'web-server-01',
                'vulnerabilities': [
                    {
                        'cve_id': 'CVE-2023-1234',
                        'description': 'Critical SQL injection vulnerability in web application',
                        'risk_level': 'Critical',
                        'cvss_score': 9.8,
                        'service': 'HTTP/80'
                    },
                    {
                        'cve_id': 'CVE-2023-5678',
                        'description': 'Cross-site scripting vulnerability',
                        'risk_level': 'High',
                        'cvss_score': 7.5,
                        'service': 'HTTP/80'
                    }
                ]
            }
        ]
    }
    
    generator = ReportGenerator()
    reports = generator.generate_all_reports(sample_results)
    print("Generated reports:")
    for format_type, filepath in reports.items():
        print(f"  {format_type.upper()}: {filepath}")