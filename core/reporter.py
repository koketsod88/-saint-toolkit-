import os
import time
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(findings, target_url, output_filename=None):
    if not output_filename:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_filename = f"saint_executive_report_{timestamp}.pdf"
    
    try:
        doc = SimpleDocTemplate(output_filename, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        story = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            textColor=colors.HexColor("#1A365D"),
            spaceAfter=6
        )
        
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor("#4A5568"),
            spaceAfter=15
        )

        story.append(Paragraph("SAINT-Toolkit Enterprise VAPT Report", title_style))
        story.append(Paragraph(f"<b>Target Scoped:</b> {target_url} | <b>Generated:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
        story.append(Spacer(1, 10))

        # Findings Summary Table
        table_data = [["Severity", "Vulnerability Category", "Endpoint / Context", "Status"]]
        for f in findings:
            table_data.append([
                f.get('severity', 'Medium'),
                f.get('title', 'Generic Finding'),
                f.get('endpoint', target_url),
                f.get('status', 'Unverified')
            ])
        
        t = Table(table_data, colWidths=[70, 180, 200, 90])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1A365D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 9),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#F7FAFC")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
            ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        
        story.append(t)
        doc.build(story)
        print(f"[+] Executive report successfully generated: {output_filename}")
        return output_filename
    except PermissionError:
        alt_filename = f"saint_report_{int(time.time())}.pdf"
        print(f"[-] Permission denied on default filename. Retrying with alternative: {alt_filename}")
        doc = SimpleDocTemplate(alt_filename, pagesize=letter)
        doc.build(story)
        print(f"[+] Executive report successfully generated: {alt_filename}")
        return alt_filename
    except Exception as e:
        print(f"[-] Critical error during PDF generation: {str(e)}")
        return None

def sync_and_generate_report(findings, target_url, output_filename=None):
    """Wrapper function to align with ui.py imports."""
    return generate_pdf_report(findings, target_url, output_filename)
