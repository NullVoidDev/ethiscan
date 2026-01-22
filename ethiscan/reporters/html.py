"""
HTML Report Generator.

Generates professional HTML reports using Bootstrap 5, Chart.js, and FontAwesome.
"""

from datetime import datetime
from pathlib import Path

from jinja2 import Template

from ethiscan.core.models import ScanResult


# Professional HTML template with Chart.js
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EthiScan Security Report - {{ target_url }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: rgba(30, 41, 59, 0.8);
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #06b6d4;
        }
        
        body { 
            background: linear-gradient(135deg, var(--bg-primary) 0%, #1a1a2e 50%, var(--bg-secondary) 100%); 
            min-height: 100vh; 
            color: var(--text-primary);
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }
        
        .glass-card {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        
        .header-banner {
            background: linear-gradient(135deg, var(--accent), #8b5cf6);
            padding: 2.5rem;
            border-radius: 16px;
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }
        
        .header-banner::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
        }
        
        .score-circle {
            width: 180px;
            height: 180px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin: 0 auto;
            position: relative;
        }
        
        .score-circle::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 50%;
            padding: 6px;
            background: linear-gradient(135deg, {{ grade_color }}, {{ grade_color }}88);
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
        }
        
        .score-value { font-size: 3rem; font-weight: 700; line-height: 1; }
        .score-grade { font-size: 1.5rem; font-weight: 600; color: {{ grade_color }}; }
        .score-label { font-size: 0.9rem; color: var(--text-secondary); }
        
        .stat-card {
            text-align: center;
            padding: 1.5rem;
            border-radius: 12px;
            transition: transform 0.2s;
        }
        
        .stat-card:hover { transform: translateY(-4px); }
        
        .stat-critical { background: linear-gradient(135deg, rgba(239,68,68,0.2), rgba(239,68,68,0.1)); border: 1px solid rgba(239,68,68,0.3); }
        .stat-high { background: linear-gradient(135deg, rgba(249,115,22,0.2), rgba(249,115,22,0.1)); border: 1px solid rgba(249,115,22,0.3); }
        .stat-medium { background: linear-gradient(135deg, rgba(234,179,8,0.2), rgba(234,179,8,0.1)); border: 1px solid rgba(234,179,8,0.3); }
        .stat-low { background: linear-gradient(135deg, rgba(34,197,94,0.2), rgba(34,197,94,0.1)); border: 1px solid rgba(34,197,94,0.3); }
        .stat-info { background: linear-gradient(135deg, rgba(6,182,212,0.2), rgba(6,182,212,0.1)); border: 1px solid rgba(6,182,212,0.3); }
        
        .stat-value { font-size: 2.5rem; font-weight: 700; }
        .stat-label { font-size: 0.85rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; }
        
        .severity-badge {
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .badge-critical { background: var(--critical); color: white; }
        .badge-high { background: var(--high); color: white; }
        .badge-medium { background: var(--medium); color: #1a1a2e; }
        .badge-low { background: var(--low); color: white; }
        .badge-info { background: var(--info); color: white; }
        
        .vuln-card {
            margin-bottom: 1rem;
            border-left: 4px solid;
            transition: all 0.2s;
        }
        
        .vuln-card:hover { transform: translateX(4px); }
        .vuln-card.critical { border-color: var(--critical); }
        .vuln-card.high { border-color: var(--high); }
        .vuln-card.medium { border-color: var(--medium); }
        .vuln-card.low { border-color: var(--low); }
        .vuln-card.info { border-color: var(--info); }
        
        .evidence-box {
            background: rgba(0,0,0,0.4);
            border-radius: 8px;
            padding: 1rem;
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .fix-box {
            background: rgba(34,197,94,0.1);
            border: 1px solid rgba(34,197,94,0.3);
            border-radius: 8px;
            padding: 1rem;
        }
        
        .section-title {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }
        
        .section-title i { color: var(--accent); font-size: 1.25rem; }
        .section-title h2 { margin: 0; font-size: 1.5rem; }
        
        .chart-container { 
            position: relative; 
            height: 280px; 
            width: 100%;
        }
        
        a { color: var(--info); text-decoration: none; }
        a:hover { color: #22d3ee; text-decoration: underline; }
        
        .accordion-button {
            background: var(--bg-secondary);
            color: var(--text-primary);
        }
        
        .accordion-button:not(.collapsed) {
            background: var(--bg-secondary);
            color: var(--text-primary);
        }
        
        .accordion-body {
            background: var(--bg-primary);
        }
        
        .executive-summary {
            background: linear-gradient(135deg, rgba(59,130,246,0.1), rgba(139,92,246,0.1));
            border: 1px solid rgba(59,130,246,0.3);
            border-radius: 12px;
            padding: 1.5rem;
        }
        
        .tech-badge {
            display: inline-block;
            background: rgba(59,130,246,0.2);
            border: 1px solid rgba(59,130,246,0.3);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 0.25rem;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <!-- Header -->
        <div class="header-banner text-center position-relative">
            <div class="position-relative">
                <h1 class="mb-2"><i class="fas fa-shield-alt me-2"></i>EthiScan Security Report</h1>
                <p class="mb-0 opacity-75">Ethical Web Vulnerability Scanner v1.0</p>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="glass-card p-4 mb-4">
            <div class="section-title">
                <i class="fas fa-clipboard-list"></i>
                <h2>Executive Summary</h2>
            </div>
            
            <div class="executive-summary mb-4">
                <div class="row align-items-center">
                    <div class="col-md-3 text-center mb-3 mb-md-0">
                        <div class="score-circle">
                            <span class="score-value">{{ score }}</span>
                            <span class="score-grade">{{ grade }}</span>
                            <span class="score-label">{{ grade_label }}</span>
                        </div>
                    </div>
                    <div class="col-md-9">
                        <h4><i class="fas fa-crosshairs me-2"></i>Target: <a href="{{ target_url }}" target="_blank">{{ target_url }}</a></h4>
                        <div class="row mt-3">
                            <div class="col-6 col-md-3">
                                <small class="text-secondary">Scan Date</small>
                                <div>{{ scan_time }}</div>
                            </div>
                            <div class="col-6 col-md-3">
                                <small class="text-secondary">Duration</small>
                                <div>{{ duration }}s</div>
                            </div>
                            <div class="col-6 col-md-3">
                                <small class="text-secondary">Scan Type</small>
                                <div><span class="badge {{ 'bg-danger' if active_scan else 'bg-success' }}">{{ 'ACTIVE' if active_scan else 'PASSIVE' }}</span></div>
                            </div>
                            <div class="col-6 col-md-3">
                                <small class="text-secondary">Findings</small>
                                <div><strong>{{ total_count }}</strong> vulnerabilities</div>
                            </div>
                        </div>
                        {% if technologies %}
                        <div class="mt-3">
                            <small class="text-secondary d-block mb-1">Technologies Detected</small>
                            {% for tech in technologies %}
                            <span class="tech-badge">{{ tech }}</span>
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-4 mb-3">
                    <p class="mb-2"><i class="fas fa-shield-check text-success me-2"></i><strong>Security Headers:</strong> {{ headers_found }}/{{ headers_total }} configured</p>
                    <div class="progress" style="height: 8px;">
                        <div class="progress-bar bg-success" style="width: {{ (headers_found / headers_total * 100) if headers_total > 0 else 0 }}%"></div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <p class="mb-2"><i class="fas fa-cookie text-warning me-2"></i><strong>Cookie Security:</strong> {{ cookie_score }}%</p>
                    <div class="progress" style="height: 8px;">
                        <div class="progress-bar bg-warning" style="width: {{ cookie_score }}%"></div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <p class="mb-2"><i class="fas fa-bug text-danger me-2"></i><strong>Vulnerability Penalty:</strong> -{{ vuln_penalty }} pts</p>
                    <div class="progress" style="height: 8px;">
                        <div class="progress-bar bg-danger" style="width: {{ vuln_penalty }}%"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Statistics -->
        <div class="glass-card p-4 mb-4">
            <div class="section-title">
                <i class="fas fa-chart-pie"></i>
                <h2>Vulnerability Distribution</h2>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-4">
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="row g-3">
                        <div class="col-6">
                            <div class="stat-card stat-critical">
                                <div class="stat-value text-danger">{{ critical_count }}</div>
                                <div class="stat-label">Critical</div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="stat-card stat-high">
                                <div class="stat-value" style="color: var(--high);">{{ high_count }}</div>
                                <div class="stat-label">High</div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="stat-card stat-medium">
                                <div class="stat-value" style="color: var(--medium);">{{ medium_count }}</div>
                                <div class="stat-label">Medium</div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="stat-card stat-low">
                                <div class="stat-value text-success">{{ low_count }}</div>
                                <div class="stat-label">Low</div>
                            </div>
                        </div>
                        <div class="col-12">
                            <div class="stat-card stat-info">
                                <div class="stat-value" style="color: var(--info);">{{ info_count }}</div>
                                <div class="stat-label">Informational</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities -->
        <div class="glass-card p-4">
            <div class="section-title">
                <i class="fas fa-bug"></i>
                <h2>Vulnerability Details ({{ total_count }})</h2>
            </div>
            
            {% if vulnerabilities %}
            <div class="accordion" id="vulnAccordion">
                {% for vuln in vulnerabilities %}
                <div class="vuln-card glass-card {{ vuln.severity|lower }} mb-3">
                    <div class="accordion-item border-0 bg-transparent">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#vuln{{ loop.index }}">
                                <span class="severity-badge badge-{{ vuln.severity|lower }} me-3">
                                    <i class="fas {{ severity_icons[vuln.severity] }} me-1"></i>
                                    {{ vuln.severity }}
                                </span>
                                <span class="flex-grow-1">{{ vuln.name }}</span>
                                <small class="text-secondary me-3">{{ vuln.module }}</small>
                            </button>
                        </h2>
                        <div id="vuln{{ loop.index }}" class="accordion-collapse collapse" data-bs-parent="#vulnAccordion">
                            <div class="accordion-body">
                                <p>{{ vuln.description }}</p>
                                
                                {% if vuln.evidence %}
                                <div class="mb-3">
                                    <h6><i class="fas fa-search me-2"></i>Evidence</h6>
                                    <div class="evidence-box"><code>{{ vuln.evidence }}</code></div>
                                </div>
                                {% endif %}
                                
                                {% if vuln.fix %}
                                <div class="mb-3">
                                    <h6><i class="fas fa-wrench me-2 text-success"></i>Recommendation</h6>
                                    <div class="fix-box">{{ vuln.fix }}</div>
                                </div>
                                {% endif %}
                                
                                <div class="row">
                                    {% if vuln.cwe_id %}
                                    <div class="col-auto">
                                        <small class="text-secondary">CWE:</small>
                                        <a href="https://cwe.mitre.org/data/definitions/{{ vuln.cwe_id.replace('CWE-', '') }}.html" target="_blank">{{ vuln.cwe_id }}</a>
                                    </div>
                                    {% endif %}
                                    {% if vuln.references %}
                                    <div class="col">
                                        <small class="text-secondary">References:</small>
                                        {% for ref in vuln.references %}
                                        <a href="{{ ref }}" target="_blank" class="ms-2"><i class="fas fa-external-link-alt"></i></a>
                                        {% endfor %}
                                    </div>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
            {% else %}
            <div class="alert alert-success d-flex align-items-center">
                <i class="fas fa-check-circle fa-2x me-3"></i>
                <div>
                    <strong>Great news!</strong> No vulnerabilities were found during this scan.
                </div>
            </div>
            {% endif %}
        </div>
        
        <!-- Footer -->
        <div class="text-center mt-4 py-3" style="opacity: 0.5;">
            <small>
                <i class="fas fa-shield-alt me-1"></i>
                Generated by EthiScan v1.0 | {{ generated_at }}
                <br>
                <span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>Use responsibly. Only scan systems you have permission to test.</span>
            </small>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Severity distribution chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [{{ critical_count }}, {{ high_count }}, {{ medium_count }}, {{ low_count }}, {{ info_count }}],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4'],
                    borderColor: '#1e293b',
                    borderWidth: 3,
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { 
                            color: '#f1f5f9',
                            padding: 15,
                            usePointStyle: true,
                            font: { size: 12 }
                        }
                    }
                },
                cutout: '60%'
            }
        });
    </script>
</body>
</html>
"""


class HtmlReporter:
    """
    HTML report generator with Bootstrap 5, Chart.js, and FontAwesome.
    
    Produces professional, visually appealing HTML reports with
    security scoring, severity charts, and detailed findings.
    """
    
    def __init__(self) -> None:
        """Initialize the HTML reporter."""
        self.extension = ".html"
        self.template = Template(HTML_TEMPLATE)
        self.severity_icons = {
            "CRITICAL": "fa-skull-crossbones",
            "HIGH": "fa-exclamation-triangle",
            "MEDIUM": "fa-exclamation-circle",
            "LOW": "fa-info-circle",
            "INFO": "fa-info",
        }
    
    def generate(self, result: ScanResult, output_path: str) -> str:
        """
        Generate an HTML report.
        
        Args:
            result: Scan result to report.
            output_path: Base output path (without extension).
            
        Returns:
            Path to the generated report file.
        """
        file_path = f"{output_path}{self.extension}"
        
        # Get security score
        from ethiscan.core.scoring import calculate_security_score
        
        # Build headers dict for scoring (from first target if available)
        headers_dict = {}
        if hasattr(result, '_headers') and result._headers:
            headers_dict = result._headers
        
        score_data = calculate_security_score(result, headers_dict)
        
        # Sort vulnerabilities by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_vulns = sorted(
            result.vulnerabilities,
            key=lambda v: severity_order.get(v.severity, 5)
        )
        
        # Extract technologies from target
        technologies = result.target.technologies if result.target.technologies else []
        
        # Render template
        html_content = self.template.render(
            target_url=result.target.url,
            ip_address=result.target.ip_address,
            server=result.target.server,
            technologies=technologies,
            scan_time=result.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
            duration=f"{result.duration:.2f}",
            active_scan=result.active_scan,
            modules_run=result.modules_run,
            total_count=result.vulnerability_count,
            critical_count=result.critical_count,
            high_count=result.high_count,
            medium_count=result.medium_count,
            low_count=result.low_count,
            info_count=result.info_count,
            
            # Score data
            score=score_data["score"],
            grade=score_data["grade"],
            grade_color=score_data["grade_color"],
            grade_label=score_data["grade_label"],
            header_score=score_data["header_score"],
            cookie_score=score_data["cookie_score"],
            vuln_penalty=score_data["vuln_penalty"],
            headers_found=score_data["headers_found"],
            headers_total=score_data["headers_total"],
            
            vulnerabilities=[
                {
                    "name": v.name,
                    "severity": v.severity,
                    "module": v.module,
                    "description": v.description,
                    "evidence": v.evidence,
                    "fix": v.fix,
                    "cwe_id": v.cwe_id,
                    "references": v.references,
                }
                for v in sorted_vulns
            ],
            severity_icons=self.severity_icons,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        
        # Write to file
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return file_path
