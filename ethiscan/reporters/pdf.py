"""
PDF Report Generator.

Generates professional PDF reports using ReportLab.
"""

from datetime import datetime
from pathlib import Path
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)

from ethiscan.core.models import ScanResult, Vulnerability


class PdfReporter:
    """
    PDF report generator using ReportLab.
    
    Produces professional PDF reports suitable for
    formal documentation and client delivery.
    """
    
    def __init__(self) -> None:
        """Initialize the PDF reporter."""
        self.extension = ".pdf"
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self) -> None:
        """Set up custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            name="Title",
            parent=self.styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#0d6efd"),
            spaceAfter=12,
        ))
        
        self.styles.add(ParagraphStyle(
            name="SectionHeader",
            parent=self.styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#333333"),
            spaceBefore=12,
            spaceAfter=6,
        ))
        
        self.styles.add(ParagraphStyle(
            name="VulnName",
            parent=self.styles["Heading3"],
            fontSize=11,
            textColor=colors.HexColor("#212529"),
            spaceBefore=6,
            spaceAfter=3,
        ))
        
        self.styles.add(ParagraphStyle(
            name="BodyText",
            parent=self.styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#333333"),
            spaceAfter=6,
        ))
        
        self.styles.add(ParagraphStyle(
            name="Evidence",
            parent=self.styles["Code"],
            fontSize=8,
            textColor=colors.HexColor("#333333"),
            backColor=colors.HexColor("#f5f5f5"),
            leftIndent=10,
            rightIndent=10,
            spaceBefore=6,
            spaceAfter=6,
        ))
    
    def generate(self, result: ScanResult, output_path: str) -> str:
        """
        Generate a PDF report.
        
        Args:
            result: Scan result to report.
            output_path: Base output path (without extension).
            
        Returns:
            Path to the generated report file.
        """
        file_path = f"{output_path}{self.extension}"
        
        # Create document
        doc = SimpleDocTemplate(
            file_path,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm,
        )
        
        # Build content
        story = []
        
        # Title
        story.append(Paragraph("EthiScan Security Report", self.styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#0d6efd")))
        story.append(Spacer(1, 12))
        
        # Target Information
        story.append(Paragraph("Target Information", self.styles["SectionHeader"]))
        
        target_data = [
            ["URL", result.target.url],
            ["IP Address", result.target.ip_address or "N/A"],
            ["Server", result.target.server or "N/A"],
            ["Scan Time", result.scan_time.strftime("%Y-%m-%d %H:%M:%S")],
            ["Duration", f"{result.duration:.2f} seconds"],
            ["Scan Type", "ACTIVE" if result.active_scan else "PASSIVE"],
        ]
        
        target_table = Table(target_data, colWidths=[4*cm, 12*cm])
        target_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8f9fa")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#333333")),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(target_table)
        story.append(Spacer(1, 12))
        
        # Summary
        story.append(Paragraph("Vulnerability Summary", self.styles["SectionHeader"]))
        
        summary_data = [
            ["Severity", "Count"],
            ["Critical", str(result.critical_count)],
            ["High", str(result.high_count)],
            ["Medium", str(result.medium_count)],
            ["Low", str(result.low_count)],
            ["Info", str(result.info_count)],
            ["Total", str(result.vulnerability_count)],
        ]
        
        severity_colors = {
            1: colors.HexColor("#dc3545"),  # Critical
            2: colors.HexColor("#fd7e14"),  # High
            3: colors.HexColor("#ffc107"),  # Medium
            4: colors.HexColor("#198754"),  # Low
            5: colors.HexColor("#0dcaf0"),  # Info
        }
        
        summary_table = Table(summary_data, colWidths=[4*cm, 3*cm])
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#333333")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
        
        for i, color in severity_colors.items():
            style_commands.append(("TEXTCOLOR", (0, i), (0, i), color))
        
        summary_table.setStyle(TableStyle(style_commands))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Vulnerabilities
        if result.vulnerabilities:
            story.append(Paragraph("Vulnerability Details", self.styles["SectionHeader"]))
            story.append(HRFlowable(width="100%", color=colors.HexColor("#dee2e6")))
            
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_vulns = sorted(
                result.vulnerabilities,
                key=lambda v: severity_order.get(v.severity, 5)
            )
            
            for i, vuln in enumerate(sorted_vulns, 1):
                story.extend(self._render_vulnerability(i, vuln))
        else:
            story.append(Spacer(1, 12))
            story.append(Paragraph(
                "✓ No vulnerabilities found!",
                ParagraphStyle(
                    "Success",
                    parent=self.styles["Normal"],
                    fontSize=12,
                    textColor=colors.HexColor("#198754"),
                )
            ))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#dee2e6")))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"Generated by EthiScan v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ParagraphStyle(
                "Footer",
                parent=self.styles["Normal"],
                fontSize=8,
                textColor=colors.HexColor("#6c757d"),
                alignment=1,  # Center
            )
        ))
        
        # Build PDF
        doc.build(story)
        
        return file_path
    
    def _render_vulnerability(self, index: int, vuln: Vulnerability) -> List:
        """Render a single vulnerability section."""
        elements = []
        
        severity_colors = {
            "CRITICAL": colors.HexColor("#dc3545"),
            "HIGH": colors.HexColor("#fd7e14"),
            "MEDIUM": colors.HexColor("#ffc107"),
            "LOW": colors.HexColor("#198754"),
            "INFO": colors.HexColor("#0dcaf0"),
        }
        
        color = severity_colors.get(vuln.severity, colors.gray)
        
        elements.append(Spacer(1, 8))
        
        # Vulnerability header
        header_text = f"<font color='{color.hexval()}'>[{vuln.severity}]</font> {index}. {vuln.name}"
        elements.append(Paragraph(header_text, self.styles["VulnName"]))
        
        # Module
        elements.append(Paragraph(
            f"<font color='#6c757d'>Module: {vuln.module}</font>",
            ParagraphStyle("Module", parent=self.styles["Normal"], fontSize=8)
        ))
        
        # Description
        elements.append(Paragraph(vuln.description, self.styles["BodyText"]))
        
        # Evidence
        if vuln.evidence:
            elements.append(Paragraph("<b>Evidence:</b>", self.styles["BodyText"]))
            # Escape HTML and limit length
            evidence = vuln.evidence[:500] + "..." if len(vuln.evidence) > 500 else vuln.evidence
            evidence = evidence.replace("<", "&lt;").replace(">", "&gt;")
            elements.append(Paragraph(evidence, self.styles["Evidence"]))
        
        # Recommendation
        if vuln.fix:
            elements.append(Paragraph("<b>Recommendation:</b>", self.styles["BodyText"]))
            elements.append(Paragraph(vuln.fix, self.styles["BodyText"]))
        
        elements.append(HRFlowable(width="100%", color=colors.HexColor("#f0f0f0")))
        
        return elements
