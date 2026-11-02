import json
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from core.verifier import PoCVerifier

def sync_and_generate_report(output_filename="saint_executive_report.pdf", target_url="http://httpbin.org/get"):
    print("[*] Running automated PoC verification suite...")
    verifier = PoCVerifier()
    
    # Run automated verification checks
    xss_valid, xss_msg = verifier.verify_xss(target_url, "q")
    sqli_valid, sqli_msg = verifier.verify_sqli(target_url, "q")

    # Structure findings for override synchronization
    findings = {
        "target": target_url,
        "overrides": {
            "XSS": {
                "status": "TRUE_POSITIVE" if xss_valid else "FALSE_POSITIVE",
                "details": xss_msg
            },
            "SQLi": {
                "status": "TRUE_POSITIVE" if sqli_valid else "FALSE_POSITIVE",
                "details": sqli_msg
            }
        }
    }

    # Automatically sync verification results to local_overrides.json
    override_path = "local_overrides.json"
    with open(override_path, "w") as f:
        json.dump(findings, f, indent=4)
    print(f"[*] Successfully synchronized verification results to {override_path}")

    # Generate ReportLab PDF Executive Report
    doc = SimpleDocTemplate(output_filename, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1a365d'),
        spaceAfter=6
    )
    
    story.append(Paragraph("SAINT Security Assessment & Hardening Report", title_style))
    story.append(Paragraph(f"<b>Target Assessed:</b> {target_url}", styles['Normal']))
    story.append(Spacer(1, 15))

    table_data = [
        ["Vulnerability Class", "Verification Status", "Details / Evidence"],
        ["Cross-Site Scripting (XSS)", findings["overrides"]["XSS"]["status"], xss_msg],
        ["SQL Injection (SQLi)", findings["overrides"]["SQLi"]["status"], sqli_msg],
    ]

    t = Table(table_data, colWidths=[140, 110, 290])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a365d')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e0')),
        ('FONTSIZE', (0,1), (-1,-1), 8),
    ]))

    story.append(t)
    doc.build(story)
    print(f"[*] Executive PDF Report generated successfully: {output_filename}")

if __name__ == "__main__":
    sync_and_generate_report()
