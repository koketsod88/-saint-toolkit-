from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from core.verifier import PoCVerifier

def generate_executive_pdf(output_filename="saint_executive_report.pdf", target_url="http://localhost:8081"):
    doc = SimpleDocTemplate(output_filename, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1a365d'),
        spaceAfter=6
    )
    
    story.append(Paragraph("SAINT Security Assessment & Hardening Report", title_style))
    story.append(Paragraph(f"<b>Target Assessed:</b> {target_url}", styles['Normal']))
    story.append(Spacer(1, 15))

    # Run automated verification checks
    verifier = PoCVerifier()
    xss_valid, xss_msg = verifier.verify_xss(target_url, "q")
    sqli_valid, sqli_msg = verifier.verify_sqli(target_url, "q")

    # Define findings table data
    table_data = [
        ["Vulnerability Class", "Verification Status", "Details / Evidence"],
        ["Cross-Site Scripting (XSS)", "TRUE POSITIVE" if xss_valid else "SAFE / SUPPRESSED", xss_msg],
        ["SQL Injection (SQLi)", "TRUE POSITIVE" if sqli_valid else "SAFE / SUPPRESSED", sqli_msg],
    ]

    t = Table(table_data, colWidths=[140, 110, 290])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a365d')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e0')),
        ('FONTSIZE', (0,1), (-1,-1), 9),
    ]))

    story.append(t)
    doc.build(story)
    print(f"[*] Executive Report generated successfully: {output_filename}")

if __name__ == "__main__":
    generate_executive_pdf()
