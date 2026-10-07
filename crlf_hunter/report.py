"""
Advanced Reporting with Multiple Formats (HTML, SARIF, JUnit, JSON, Markdown)
Professional-grade evidence collection and report generation
"""

import json
import html
import time
import os
from typing import Dict, List, Any, Optional, TextIO
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import base64
import hashlib


class ReportFormat(Enum):
    """Supported report formats"""
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"
    JUNIT = "junit"
    MARKDOWN = "markdown"
    CSV = "csv"
    XML = "xml"


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Individual vulnerability finding"""
    id: str
    title: str
    description: str
    severity: Severity
    vulnerability_type: str
    target_url: str
    injection_point: str
    payload: str
    evidence: str
    curl_command: str
    raw_request: bytes
    raw_response: bytes
    confidence: str
    timestamp: str
    tags: List[str] = field(default_factory=list)
    cve_references: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d["raw_request"] = self.raw_request.decode("utf-8", errors="ignore")[:5000]
        d["raw_response"] = self.raw_response.decode("utf-8", errors="ignore")[:5000]
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanMetadata:
    """Scan metadata and statistics"""
    scan_id: str
    start_time: str
    end_time: str
    duration: float
    targets_scanned: int
    total_requests: int
    vulnerabilities_found: int
    findings_by_severity: Dict[str, int]
    findings_by_type: Dict[str, int]
    tool_version: str = "crlf-hunter/2.0"
    config: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ReportGenerator:
    """Generate reports in multiple formats"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: List[Finding] = []
        self.metadata: Optional[ScanMetadata] = None
    
    def add_finding(self, finding: Finding):
        """Add a finding to the report"""
        self.findings.append(finding)
    
    def set_metadata(self, metadata: ScanMetadata):
        """Set scan metadata"""
        self.metadata = metadata
    
    def generate_json(self, filepath: str = None) -> str:
        """Generate JSON report"""
        if filepath is None:
            filepath = self.output_dir / f"crlf-hunter-report-{int(time.time())}.json"
        
        report = {
            "metadata": self.metadata.to_dict() if self.metadata else {},
            "findings": [f.to_dict() for f in self.findings],
            "summary": self._generate_summary(),
        }
        
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        return str(filepath)
    
    def generate_html(self, filepath: str = None) -> str:
        """Generate HTML report with embedded evidence"""
        if filepath is None:
            filepath = self.output_dir / f"crlf-hunter-report-{int(time.time())}.html"
        
        html_content = self._build_html_report()
        
        with open(filepath, "w") as f:
            f.write(html_content)
        
        return str(filepath)
    
    def generate_sarif(self, filepath: str = None) -> str:
        """Generate SARIF report for CI/CD integration"""
        if filepath is None:
            filepath = self.output_dir / f"crlf-hunter-report-{int(time.time())}.sarif"
        
        sarif = self._build_sarif()
        
        with open(filepath, "w") as f:
            json.dump(sarif, f, indent=2)
        
        return str(filepath)
    
    def generate_junit(self, filepath: str = None) -> str:
        """Generate JUnit XML report for CI/CD"""
        if filepath is None:
            filepath = self.output_dir / f"crlf-hunter-report-{int(time.time())}.xml"
        
        junit = self._build_junit()
        
        with open(filepath, "w") as f:
            f.write(junit)
        
        return str(filepath)
    
    def generate_markdown(self, filepath: str = None) -> str:
        """Generate Markdown report"""
        if filepath is None:
            filepath = self.output_dir / f"crlf-hunter-report-{int(time.time())}.md"
        
        md = self._build_markdown()
        
        with open(filepath, "w") as f:
            f.write(md)
        
        return str(filepath)
    
    def generate_csv(self, filepath: str = None) -> str:
        """Generate CSV report for spreadsheet analysis"""
        if filepath is None:
            filepath = self.output_dir / f"crlf-hunter-report-{int(time.time())}.csv"
        
        import csv
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "ID", "Severity", "Type", "Target URL", "Injection Point",
                "Payload", "Evidence", "Confidence", "CVE References", "Timestamp"
            ])
            for finding in self.findings:
                writer.writerow([
                    finding.id,
                    finding.severity.value,
                    finding.vulnerability_type,
                    finding.target_url,
                    finding.injection_point,
                    finding.payload[:200],
                    finding.evidence[:200],
                    finding.confidence,
                    ", ".join(finding.cve_references),
                    finding.timestamp,
                ])
        
        return str(filepath)
    
    def generate_all(self, base_name: str = None) -> Dict[str, str]:
        """Generate all report formats"""
        if base_name is None:
            base_name = f"crlf-hunter-report-{int(time.time())}"
        
        results = {}
        results["json"] = self.generate_json(str(self.output_dir / f"{base_name}.json"))
        results["html"] = self.generate_html(str(self.output_dir / f"{base_name}.html"))
        results["sarif"] = self.generate_sarif(str(self.output_dir / f"{base_name}.sarif"))
        results["junit"] = self.generate_junit(str(self.output_dir / f"{base_name}.xml"))
        results["markdown"] = self.generate_markdown(str(self.output_dir / f"{base_name}.md"))
        results["csv"] = self.generate_csv(str(self.output_dir / f"{base_name}.csv"))
        
        return results
    
    def _generate_summary(self) -> Dict:
        """Generate summary statistics"""
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        
        for f in self.findings:
            by_severity[f.severity.value] += 1
            by_type[f.vulnerability_type] += 1
        
        return {
            "total_findings": len(self.findings),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
        }
    
    def _build_html_report(self) -> str:
        """Build comprehensive HTML report"""
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#20c997",
            "info": "#17a2b8",
        }
        
        # Group findings by severity
        findings_by_severity = defaultdict(list)
        for f in self.findings:
            findings_by_severity[f.severity.value].append(f)
        
        severity_order = ["critical", "high", "medium", "low", "info"]
        
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            "<title>CRLF Hunter - Security Scan Report</title>",
            self._get_html_styles(),
            "</head>",
            "<body>",
            "<div class='container'>",
            self._build_html_header(),
            self._build_html_summary(),
        ]
        
        # Findings sections
        for severity in severity_order:
            if severity in findings_by_severity:
                html_parts.append(self._build_html_findings_section(severity, findings_by_severity[severity], severity_colors[severity]))
        
        html_parts.extend([
            self._build_html_footer(),
            "</div>",
            self._get_html_scripts(),
            "</body>",
            "</html>",
        ])
        
        return "\n".join(html_parts)
    
    def _get_html_styles_v2(self) -> str:
        return """
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
            .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
            
            /* Header */
            header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }
            h1 { font-size: 2.5rem; margin-bottom: 10px; }
            .subtitle { opacity: 0.9; font-size: 1.1rem; }
            .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px; }
            .meta-card { background: rgba(255,255,255,0.1); padding: 15px; border-radius: 6px; }
            .meta-card h3 { font-size: 0.85rem; text-transform: uppercase; opacity: 0.8; margin-bottom: 5px; }
            .meta-card p { font-size: 1.5rem; font-weight: bold; }
            
            /* Summary Cards */
            .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
            .summary-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; border-left: 4px solid; }
            .summary-card.critical { border-color: #dc3545; }
            .summary-card.high { border-color: #fd7e14; }
            .summary-card.medium { border-color: #ffc107; }
            .summary-card.low { border-color: #20c997; }
            .summary-card.info { border-color: #17a2b8; }
            .summary-card h3 { font-size: 2rem; margin-bottom: 5px; }
            .summary-card p { color: #666; font-size: 0.9rem; }
            
            /* Filters */
            .filter-bar { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
            .filter-row { display: flex; gap: 15px; flex-wrap: wrap; align-items: center; }
            .filter-group { display: flex; align-items: center; gap: 8px; }
            .filter-group label { font-weight: 600; color: #555; }
            .filter-group select, .filter-group input { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 0.9rem; }
            .filter-group input[type="text"] { flex: 1; min-width: 200px; }
            
            /* Findings Container */
            .findings-container { display: flex; flex-direction: column; gap: 15px; }
            
            /* Finding Cards */
            .finding-card { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; transition: box-shadow 0.2s; }
            .finding-card:hover { box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
            .finding-header { padding: 15px 20px; display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; cursor: pointer; }
            .finding-title-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
            .finding-title { font-size: 1.1rem; font-weight: 600; margin: 0; }
            .severity-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; color: white; text-transform: uppercase; }
            .finding-meta { display: flex; gap: 15px; flex-wrap: wrap; font-size: 0.85rem; color: #666; margin-top: 8px; }
            .meta-item { background: #f8f9fa; padding: 2px 8px; border-radius: 4px; }
            .meta-item strong { color: #333; }
            
            .finding-body { padding: 0 20px 20px; display: none; }
            .finding-card.expanded .finding-body { display: block; animation: slideDown 0.3s ease; }
            @keyframes slideDown { from { opacity: 0; max-height: 0; } to { opacity: 1; max-height: 5000px; } }
            
            .finding-section { margin-bottom: 20px; }
            .finding-section h4 { font-size: 0.95rem; color: #444; margin-bottom: 8px; border-bottom: 1px solid #eee; padding-bottom: 4px; }
            .code-block { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; font-family: 'Monaco', 'Consolas', monospace; font-size: 0.85rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
            .curl-block { background: #2d2d2d; }
            
            .finding-tags { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 15px; }
            .tag { background: #e9ecef; padding: 2px 8px; border-radius: 3px; font-size: 0.75rem; }
            
            /* Footer */
            footer { text-align: center; padding: 20px; color: #888; font-size: 0.9rem; }
            
            /* Responsive */
            @media (max-width: 768px) {
                .container { padding: 10px; }
                h1 { font-size: 1.8rem; }
                .filter-row { flex-direction: column; align-items: stretch; }
                .filter-group input[type="text"] { min-width: 100%; }
            }
            
            /* Hidden utility */
            .hidden { display: none !important; }
        </style>
        """

    def _get_html_styles(self) -> str:
        """Legacy styles for backward compatibility"""
        return self._get_html_styles_v2()

    def _build_html_header_v2(self) -> str:
        meta = self.metadata
        return f"""
        <header>
            <h1>🔍 CRLF Hunter Security Scan Report</h1>
            <p class='subtitle'>CRLF Injection / HTTP Response Splitting Detection</p>
            <div class='meta-grid'>
                <div class='meta-card'><h3>Scan ID</h3><p>{meta.scan_id if meta else 'N/A'}</p></div>
                <div class='meta-card'><h3>Started</h3><p>{meta.start_time if meta else 'N/A'}</p></div>
                <div class='meta-card'><h3>Completed</h3><p>{meta.end_time if meta else 'N/A'}</p></div>
                <div class='meta-card'><h3>Duration</h3><p>{meta.duration:.1f}s</p></div>
                <div class='meta-card'><h3>Targets</h3><p>{meta.targets_scanned if meta else 0}</p></div>
                <div class='meta-card'><h3>Requests</h3><p>{meta.total_requests if meta else 0}</p></div>
            </div>
        </header>
        """

    def _build_html_summary_v2(self, severity_summary: str) -> str:
        return f"""
        <div class='summary-grid'>
            {severity_summary}
        </div>
        """

    def _build_html_filters(self) -> str:
        return """
        <div class='filter-bar'>
            <div class='filter-row'>
                <div class='filter-group'>
                    <label>Search:</label>
                    <input type="text" id="searchInput" placeholder="Search findings..." oninput="filterFindings()">
                </div>
                <div class='filter-group'>
                    <label>Severity:</label>
                    <select id="severityFilter" onchange="filterFindings()">
                        <option value="">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                    </select>
                </div>
                <div class='filter-group'>
                    <label>Type:</label>
                    <select id="typeFilter" onchange="filterFindings()">
                        <option value="">All Types</option>
                    </select>
                </div>
                <div class='filter-group'>
                    <label>Status:</label>
                    <select id="statusFilter" onchange="filterFindings()">
                        <option value="">All</option>
                        <option value="expanded">Expanded</option>
                        <option value="collapsed">Collapsed</option>
                    </select>
                </div>
            </div>
        </div>
        """

    def _build_html_footer(self) -> str:
        return f"""
        <footer>
            <p>Generated by CRLF Hunter v2.0 | {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}</p>
            <p>For authorized security testing only</p>
        </footer>
        """

    def _get_html_scripts_v2(self) -> str:
        return """
        <script>
            // Initialize type filter options
            document.addEventListener('DOMContentLoaded', function() {
                const typeFilter = document.getElementById('typeFilter');
                const types = new Set();
                document.querySelectorAll('.finding-card').forEach(card => {
                    types.add(card.dataset.type);
                });
                Array.from(types).sort().forEach(type => {
                    const option = document.createElement('option');
                    option.value = type;
                    option.textContent = type;
                    typeFilter.appendChild(option);
                });
                
                // Add click handlers for collapsible cards
                document.querySelectorAll('.finding-header').forEach(header => {
                    header.addEventListener('click', function() {
                        this.parentElement.classList.toggle('expanded');
                    });
                });
            });
            
            function filterFindings() {
                const searchTerm = document.getElementById('searchInput').value.toLowerCase();
                const severityFilter = document.getElementById('severityFilter').value;
                const typeFilter = document.getElementById('typeFilter').value;
                const statusFilter = document.getElementById('statusFilter').value;
                
                document.querySelectorAll('.finding-card').forEach(card => {
                    const text = card.textContent.toLowerCase();
                    const severity = card.dataset.severity;
                    const type = card.dataset.type;
                    const isExpanded = card.classList.contains('expanded');
                    
                    let show = true;
                    
                    if (searchTerm && !text.includes(searchTerm)) {
                        show = false;
                    }
                    
                    if (severityFilter && severity !== severityFilter) {
                        show = false;
                    }
                    
                    if (typeFilter && type !== typeFilter) {
                        show = false;
                    }
                    
                    if (statusFilter === 'expanded' && !isExpanded) {
                        show = false;
                    } else if (statusFilter === 'collapsed' && isExpanded) {
                        show = false;
                    }
                    
                    card.style.display = show ? 'block' : 'none';
                });
            }
            
            // Toggle individual finding
            function toggleFinding(card) {
                card.classList.toggle('expanded');
            }
        </script>
        """
    
    def _build_html_header(self) -> str:
        meta = self.metadata
        return f"""
        <header>
            <h1>🔍 CRLF Hunter Security Scan Report</h1>
            <p class='subtitle'>CRLF Injection / HTTP Response Splitting Detection</p>
            <div class='meta-grid'>
                <div class='meta-card'><h3>Scan ID</h3><p>{meta.scan_id if meta else 'N/A'}</p></div>
                <div class='meta-card'><h3>Started</h3><p>{meta.start_time if meta else 'N/A'}</p></div>
                <div class='meta-card'><h3>Completed</h3><p>{meta.end_time if meta else 'N/A'}</p></div>
                <div class='meta-card'><h3>Duration</h3><p>{meta.duration:.1f}s</p></div>
                <div class='meta-card'><h3>Targets</h3><p>{meta.targets_scanned if meta else 0}</p></div>
                <div class='meta-card'><h3>Requests</h3><p>{meta.total_requests if meta else 0}</p></div>
            </div>
        </header>
        """
    
    def _build_html_summary(self) -> str:
        if not self.metadata:
            return ""
        
        return f"""
        <div class='summary-cards'>
            <div class='summary-card critical'><h3>{self.metadata.findings_by_severity.get('critical', 0)}</h3><p>Critical</p></div>
            <div class='summary-card high'><h3>{self.metadata.findings_by_severity.get('high', 0)}</h3><p>High</p></div>
            <div class='summary-card medium'><h3>{self.metadata.findings_by_severity.get('medium', 0)}</h3><p>Medium</p></div>
            <div class='summary-card low'><h3>{self.metadata.findings_by_severity.get('low', 0)}</h3><p>Low</p></div>
            <div class='summary-card info'><h3>{self.metadata.findings_by_severity.get('info', 0)}</h3><p>Info</p></div>
        </div>
        """
    
    def _build_html_findings_section(self, severity: str, findings: List[Finding], color: str) -> str:
        badge_html = f"<span class='badge' style='background: {color}'>{severity.upper()} ({len(findings)})</span>"
        
        items = []
        for f in findings:
            items.append(f"""
            <div class='finding'>
                <div class='finding-header collapsible' onclick='toggleFinding(this)'>
                    <span class='finding-title'>{html.escape(f.title)}</span>
                    <span class='finding-meta'>
                        <span>🎯 {html.escape(f.injection_point)}</span>
                        <span>🔗 {html.escape(f.target_url[:80])}{'...' if len(f.target_url) > 80 else ''}</span>
                        <span>🏷️ {f.vulnerability_type}</span>
                    </span>
                </div>
                <div class='finding-body'>
                    <div class='finding-field'>
                        <label>Description</label>
                        <p>{html.escape(f.description)}</p>
                    </div>
                    <div class='finding-field'>
                        <label>Payload</label>
                        <div class='evidence-box'>{html.escape(f.payload)}</div>
                    </div>
                    <div class='finding-field'>
                        <label>Evidence</label>
                        <div class='evidence-box'>{html.escape(f.evidence)}</div>
                    </div>
                    <div class='finding-field'>
                        <label>cURL Command (for reproduction)</label>
                        <div class='curl-box'>{html.escape(f.curl_command)}</div>
                    </div>
                    <div class='finding-field'>
                        <label>Confidence</label>
                        <code>{f.confidence}</code>
                    </div>
                    <div class='finding-field'>
                        <label>Timestamp</label>
                        <code>{f.timestamp}</code>
                    </div>
                    <div class='tags'>
                        {''.join(f'<span class="tag">{html.escape(t)}</span>' for t in f.tags)}
                    </div>
                </div>
            </div>
            """)
        
        return f"""
        <section class='section'>
            <div class='section-header'>
                <h2>Findings: {badge_html}</h2>
            </div>
            <div class='findings-list'>
                {''.join(items)}
            </div>
        </section>
        """
    
    def _build_html_footer(self) -> str:
        return f"""
        <footer>
            <p>Generated by CRLF Hunter v2.0 | {datetime.utcnow().isoformat()}Z</p>
            <p>For authorized security testing only</p>
        </footer>
        """
    
    def _get_html_scripts(self) -> str:
        return """
        <script>
            function toggleFinding(header) {
                const body = header.nextElementSibling;
                body.classList.toggle('hidden');
            }
            // Auto-expand critical/high findings
            document.querySelectorAll('.finding-header').forEach(h => {
                if (h.textContent.includes('CRITICAL') || h.textContent.includes('HIGH')) {
                    h.nextElementSibling.classList.remove('hidden');
                }
            });
        </script>
        """
    
    def _build_sarif(self) -> Dict:
        """Build SARIF 2.1.0 report"""
        rules = {}
        results = []
        
        for finding in self.findings:
            rule_id = finding.vulnerability_type
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.description},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": self._severity_to_sarif_level(finding.severity)},
                    "helpUri": "https://github.com/crlf-hunter/docs",
                    "properties": {
                        "tags": finding.tags,
                        "precision": "high",
                        "problem.severity": finding.severity.value,
                    }
                }
            
            # Parse location from target URL
            uri = finding.target_url
            
            results.append({
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1}
                    }
                }],
                "partialFingerprints": {
                    "payload": hashlib.md5(finding.payload.encode()).hexdigest()[:16]
                },
                "properties": {
                    "injectionPoint": finding.injection_point,
                    "payload": finding.payload,
                    "evidence": finding.evidence,
                    "curlCommand": finding.curl_command,
                    "confidence": finding.confidence,
                }
            })
        
        return {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CRLF Hunter",
                        "version": "2.0",
                        "informationUri": "https://github.com/crlf-hunter",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": self.metadata.start_time if self.metadata else datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    "endTimeUtc": self.metadata.end_time if self.metadata else datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                }]
            }]
        }
    
    def _severity_to_sarif_level(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "note")
    
    def _build_junit(self) -> str:
        """Build JUnit XML report"""
        testsuite_attrs = {
            "name": "CRLF Hunter Security Scan",
            "tests": str(len(self.findings)),
            "failures": str(sum(1 for f in self.findings if f.severity in [Severity.CRITICAL, Severity.HIGH])),
            "errors": "0",
            "skipped": "0",
            "time": str(self.metadata.duration if self.metadata else 0),
            "timestamp": self.metadata.start_time if self.metadata else datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }
        
        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        lines.append(f'<testsuite {" ".join(f"{k}=\"{v}\"" for k, v in testsuite_attrs.items())}>')
        
        # Properties
        if self.metadata:
            lines.append("  <properties>")
            for k, v in self.metadata.config.items():
                lines.append(f'    <property name="{k}" value="{v}"/>')
            lines.append("  </properties>")
        
        # Test cases (each finding)
        for finding in self.findings:
            classname = finding.vulnerability_type
            name = finding.title
            
            lines.append(f'  <testcase classname="{classname}" name="{html.escape(name)}" time="0">')
            
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                lines.append(f'    <failure message="{html.escape(finding.description)}" type="vulnerability">')
                lines.append(f"      <![CDATA[")
                lines.append(f"Target: {finding.target_url}")
                lines.append(f"Injection Point: {finding.injection_point}")
                lines.append(f"Payload: {finding.payload}")
                lines.append(f"Evidence: {finding.evidence}")
                lines.append(f"CURL: {finding.curl_command}")
                lines.append(f"Severity: {finding.severity.value}")
                lines.append(f"Confidence: {finding.confidence}")
                lines.append(f"Tags: {', '.join(finding.tags)}")
                lines.append(f"      ]]>")
                lines.append("    </failure>")
            
            lines.append("    <system-out>")
            lines.append(f"      <![CDATA[{html.escape(finding.raw_response.decode('utf-8', errors='ignore')[:2000])}]]>")
            lines.append("    </system-out>")
            lines.append("  </testcase>")
        
        lines.append("</testsuite>")
        return "\n".join(lines)
    
    def _build_markdown(self) -> str:
        """Build Markdown report"""
        lines = [
            "# CRLF Hunter Security Scan Report",
            "",
            f"**Scan ID:** {self.metadata.scan_id if self.metadata else 'N/A'}  ",
            f"**Started:** {self.metadata.start_time if self.metadata else 'N/A'}  ",
            f"**Completed:** {self.metadata.end_time if self.metadata else 'N/A'}  ",
            f"**Duration:** {self.metadata.duration:.1f}s  ",
            f"**Targets:** {self.metadata.targets_scanned if self.metadata else 0}  ",
            f"**Total Requests:** {self.metadata.total_requests if self.metadata else 0}  ",
            f"**Vulnerabilities Found:** {len(self.findings)}  ",
            "",
            "## Summary",
            "",
        ]
        
        if self.metadata:
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = self.metadata.findings_by_severity.get(sev, 0)
                if count > 0:
                    lines.append(f"| {sev.capitalize()} | {count} |")
            lines.append("")
        
        # Group by severity
        findings_by_severity = defaultdict(list)
        for f in self.findings:
            findings_by_severity[f.severity.value].append(f)
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in findings_by_severity:
                lines.append(f"## {severity.capitalize()} Severity Findings")
                lines.append("")
                
                for f in findings_by_severity[severity]:
                    lines.append(f"### {f.title}")
                    lines.append("")
                    lines.append(f"- **Target:** `{f.target_url}`")
                    lines.append(f"- **Injection Point:** `{f.injection_point}`")
                    lines.append(f"- **Type:** {f.vulnerability_type}")
                    lines.append(f"- **Confidence:** {f.confidence}")
                    lines.append(f"- **Timestamp:** {f.timestamp}")
                    lines.append("")
                    lines.append(f"**Description:** {f.description}")
                    lines.append("")
                    lines.append("**Payload:**")
                    lines.append("```")
                    lines.append(f.payload)
                    lines.append("```")
                    lines.append("")
                    lines.append("**Evidence:**")
                    lines.append("```")
                    lines.append(f.evidence)
                    lines.append("```")
                    lines.append("")
                    lines.append("**cURL for Reproduction:**")
                    lines.append("```bash")
                    lines.append(f.curl_command)
                    lines.append("```")
                    lines.append("")
                    
                    if f.tags:
                        lines.append(f"**Tags:** {', '.join(f.tags)}")
                        lines.append("")
                    
                    if f.cve_references:
                        lines.append(f"**CVE References:** {', '.join(f.cve_references)}")
                        lines.append("")
                    
                    lines.append("---")
                    lines.append("")
        
        return "\n".join(lines)


class LiveReporter:
    """Real-time terminal reporting with colors and progress"""
    
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.stats = {
            "total": 0,
            "completed": 0,
            "vulnerable": 0,
            "errors": 0,
            "by_type": defaultdict(int),
            "by_severity": defaultdict(int),
        }
        self.start_time = time.time()
        self._last_update = 0
        self._update_interval = 0.5  # seconds
    
    def update(self, **kwargs):
        """Update statistics"""
        for k, v in kwargs.items():
            if k in self.stats:
                self.stats[k] = v
    
    def increment(self, key: str, value: int = 1):
        """Increment a counter"""
        if key in self.stats:
            self.stats[key] += value
    
    def print_progress(self, current_target: str = "", current_payload: str = ""):
        """Print live progress bar"""
        if self.quiet:
            return
        
        now = time.time()
        if now - self._last_update < self._update_interval:
            return
        self._last_update = now
        
        elapsed = now - self.start_time
        total = self.stats["total"]
        completed = self.stats["completed"]
        
        if total > 0:
            pct = completed / total * 100
            bar_width = 40
            filled = int(bar_width * completed / total)
            bar = "█" * filled + "░" * (bar_width - filled)
            
            rate = completed / elapsed if elapsed > 0 else 0
            eta = (total - completed) / rate if rate > 0 else 0
            
            line = f"\r[{bar}] {pct:.1f}% ({completed}/{total}) | "
            line += f"Vuln: {self.stats['vulnerable']} | Err: {self.stats['errors']} | "
            line += f"{rate:.1f}/s | ETA: {eta:.0f}s"
            
            if current_target:
                line += f" | {current_target[:50]}"
            
            print(line, end="", flush=True)
    
    def print_finding(self, finding: Finding):
        """Print a finding in real-time"""
        if self.quiet:
            return
        
        # Clear progress line
        print("\r" + " " * 120 + "\r", end="")
        
        severity_colors = {
            Severity.CRITICAL: "\033[91m\033[1m",
            Severity.HIGH: "\033[91m",
            Severity.MEDIUM: "\033[93m",
            Severity.LOW: "\033[92m",
            Severity.INFO: "\033[96m",
        }
        reset = "\033[0m"
        color = severity_colors.get(finding.severity, "")
        
        print(f"{color}[{finding.severity.value.upper()}]{reset} {finding.title}")
        print(f"  Target: {finding.target_url}")
        print(f"  Injection: {finding.injection_point}")
        print(f"  Evidence: {finding.evidence[:100]}")
        print(f"  cURL: {finding.curl_command[:120]}")
        
        if self.verbose:
            print(f"  Payload: {finding.payload}")
            print(f"  Request: {finding.raw_request.decode('utf-8', errors='ignore')[:500]}")
            print(f"  Response: {finding.raw_response.decode('utf-8', errors='ignore')[:500]}")
        
        print()
    
    def print_summary(self):
        """Print final summary"""
        if self.quiet:
            return
        
        elapsed = time.time() - self.start_time
        
        print("\n" + "=" * 70)
        print(f"SCAN COMPLETE in {elapsed:.1f}s")
        print("=" * 70)
        print(f"Total Requests:  {self.stats['completed']}")
        print(f"Vulnerabilities: {self.stats['vulnerable']}")
        print(f"Errors:          {self.stats['errors']}")
        
        if self.stats["by_severity"]:
            print("\nBy Severity:")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = self.stats["by_severity"].get(sev, 0)
                if count > 0:
                    print(f"  {sev.capitalize():8}: {count}")
        
        if self.stats["by_type"]:
            print("\nBy Type:")
            for typ, count in sorted(self.stats["by_type"].items(), key=lambda x: -x[1]):
                print(f"  {typ}: {count}")


def create_finding_from_result(
    result: Any,  # AnalysisResult
    target_url: str,
    injection_point: str,
    payload: str,
    curl_command: str,
    raw_request: bytes,
    raw_response: bytes,
    payload_info: Dict,
) -> Finding:
    """Create Finding from analysis result"""
    
    # Map vulnerability type to severity
    severity_map = {
        "response_splitting": Severity.CRITICAL,
        "cache_poisoning": Severity.CRITICAL,
        "request_smuggling": Severity.CRITICAL,
        "header_injection": Severity.HIGH,
        "cookie_injection": Severity.HIGH,
        "xss_via_splitting": Severity.HIGH,
        "open_redirect": Severity.MEDIUM,
        "reflection_only": Severity.INFO,
        "error_disclosure": Severity.LOW,
    }
    
    vuln_type = result.vulnerability_type.value if hasattr(result.vulnerability_type, 'value') else str(result.vulnerability_type)
    severity = severity_map.get(vuln_type, Severity.MEDIUM)
    
    # Confidence mapping
    confidence_map = {
        "confirmed": "Confirmed",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }
    confidence = confidence_map.get(
        result.confidence.value if hasattr(result.confidence, 'value') else str(result.confidence),
        "Medium"
    )
    
    return Finding(
        id=hashlib.md5(f"{target_url}{injection_point}{payload}".encode()).hexdigest()[:12],
        title=f"{vuln_type.replace('_', ' ').title()} in {injection_point}",
        description=f"CRLF injection vulnerability allowing {vuln_type.replace('_', ' ')} via {injection_point} parameter",
        severity=severity,
        vulnerability_type=vuln_type,
        target_url=target_url,
        injection_point=injection_point,
        payload=payload,
        evidence=result.evidences[0].raw_snippet if result.evidences else "No evidence",
        curl_command=curl_command,
        raw_request=raw_request,
        raw_response=raw_response,
        confidence=confidence,
        timestamp=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        tags=payload_info.get("tags", []) if payload_info else [],
        cve_references=payload_info.get("cve_references", []) if payload_info else [],
        remediation=_get_remediation(vuln_type),
        references=_get_references(vuln_type),
    )


def _get_remediation(vuln_type: str) -> str:
    """Get remediation advice for vulnerability type"""
    remediations = {
        "response_splitting": "Implement strict input validation and output encoding. Reject or sanitize CR/LF characters in user input. Use secure HTTP libraries that prevent header injection.",
        "cache_poisoning": "Implement proper cache key validation. Use Vary headers correctly. Validate and sanitize all user input before using in headers.",
        "request_smuggling": "Use a consistent HTTP parsing approach across all infrastructure. Disable HTTP/1.0 support. Implement strict Content-Length and Transfer-Encoding validation.",
        "header_injection": "Validate and sanitize all user-supplied input used in HTTP headers. Reject CR/LF characters. Use allowlists for header values.",
        "cookie_injection": "Sanitize cookie values. Use HttpOnly and Secure flags. Implement SameSite cookie attributes.",
        "xss_via_splitting": "Implement Content Security Policy (CSP). Sanitize all output. Validate and encode user input in HTTP responses.",
        "open_redirect": "Validate redirect URLs against allowlist. Use relative URLs only. Implement redirect confirmation pages.",
        "reflection_only": "Monitor for potential escalation. Ensure proper output encoding is in place.",
        "error_disclosure": "Disable detailed error messages in production. Implement custom error pages.",
    }
    return remediations.get(vuln_type, "Implement proper input validation and output encoding.")


def _get_references(vuln_type: str) -> List[str]:
    """Get reference links for vulnerability type"""
    refs = {
        "response_splitting": [
            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
            "https://cwe.mitre.org/data/definitions/113.html",
        ],
        "cache_poisoning": [
            "https://portswigger.net/web-cache-poisoning",
            "https://owasp.org/www-community/attacks/Cache_Poisoning",
        ],
        "request_smuggling": [
            "https://portswigger.net/web-security/request-smuggling",
            "https://httpwg.org/specs/rfc9112.html#rfc.section.11.5",
        ],
        "header_injection": [
            "https://cwe.mitre.org/data/definitions/113.html",
            "https://owasp.org/www-community/attacks/HTTP_Header_Injection",
        ],
    }
    return refs.get(vuln_type, [])


# Legacy compatibility
def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    crlf-hunter v2.0.0                        ║
║         CRLF Injection / HTTP Response Splitting Scanner     ║
║                    FOR AUTHORIZED TESTING ONLY               ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_target_info(target, method, header_fuzz, body_fuzz, delay, timeout):
    """Print target configuration"""
    print(f"\033[1mTarget:\033[0m {target.original_url}")
    print(f"\033[1mMethod:\033[0m {method}")
    print(f"\033[1mHost:\033[0m {target.host}:{target.port} ({target.scheme})")
    print(f"\033[1mPath:\033[0m {target.path}")
    print(f"\033[1mQuery params:\033[0m {list(target.params.keys())}")
    print(f"\033[1mHeader fuzz:\033[0m {'Enabled' if header_fuzz else 'Disabled'}")
    print(f"\033[1mBody fuzz:\033[0m {'Enabled' if body_fuzz else 'Disabled'}")
    print(f"\033[1mDelay:\033[0m {delay}s")
    print(f"\033[1mTimeout:\033[0m {timeout}s")
    print()


def print_test_result(case_num, total, injection_point, payload, vulnerable, evidence, verbose=False, raw_request=None, raw_response=None):
    """Print a single test result"""
    ip_str = f"{injection_point.type}:{injection_point.name}"
    payload_short = payload[:50] + "..." if len(payload) > 50 else payload
    
    if vulnerable:
        status = "\033[91m\033[1m[VULNERABLE]\033[0m"
        evidence_str = f"\033[91m -> {evidence}\033[0m"
    else:
        status = "\033[92m[SAFE]\033[0m"
        evidence_str = ""
    
    print(f"\033[96m[{case_num}/{total}]\033[0m {ip_str:<30} {status}{evidence_str}")
    
    if verbose:
        print(f"  \033[93mPayload:\033[0m {payload}")
        if raw_request:
            print(f"  \033[93mRequest:\033[0m")
            for line in raw_request.decode('utf-8', errors='ignore').split('\n')[:20]:
                print(f"    {line}")
        if raw_response:
            print(f"  \033[93mResponse:\033[0m")
            for line in raw_response.decode('utf-8', errors='ignore').split('\n')[:20]:
                print(f"    {line}")
        print()


def print_summary(vulnerable_count, total_count):
    """Print scan summary"""
    print(f"\n\033[1m{'='*60}\033[0m")
    if vulnerable_count > 0:
        print(f"\033[91m\033[1mSCAN COMPLETE: {vulnerable_count} VULNERABLE out of {total_count} tests\033[0m")
    else:
        print(f"\033[92m\033[1mSCAN COMPLETE: No vulnerabilities found in {total_count} tests\033[0m")
    print(f"\033[1m{'='*60}\033[0m")


def write_json_report(results, output_file, target_url, scan_config):
    """Write full JSON report (legacy)"""
    report = {
        "tool": "crlf-hunter",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "target": target_url,
        "config": scan_config,
        "summary": {
            "total_tests": len(results),
            "vulnerable": sum(1 for r in results if r["vulnerable"]),
            "safe": sum(1 for r in results if not r["vulnerable"]),
        },
        "results": results
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n\033[92mJSON report written to:\033[0m {output_file}")


def build_result_object(url, injection_point, payload, vulnerable, evidence, raw_snippet, detail_type):
    """Build a single result object for JSON (legacy)"""
    return {
        "url": url,
        "injection_point": {
            "type": injection_point.type,
            "name": injection_point.name,
            "original_value": injection_point.original_value
        },
        "payload": payload,
        "vulnerable": vulnerable,
        "evidence": evidence,
        "raw_snippet": raw_snippet,
        "detection_type": detail_type
    }