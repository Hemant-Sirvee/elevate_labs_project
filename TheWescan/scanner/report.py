# scanner/report.py (improved)
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

MITIGATIONS = {
    "XSS": "Validate and escape untrusted input on output. Use context-aware encoding. Implement CSP.",
    "SQLi": "Use parameterized queries / prepared statements. Avoid string concatenation. Enforce least privilege on DB user.",
    "LFI": "Validate/normalize file paths. Avoid direct inclusion of user-supplied filenames. Use allowlists.",
    "XXE": "Disable external entity resolution in XML parsers. Use safer parsers and validate XML schemas."
}

def create_pdf_report(filename, job):
    """
    job: dict { target, status, findings: [ {vuln_type,url,param,payload,evidence} ] }
    """
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    # Cover page
    c.setFont("Helvetica-Bold", 20)
    c.drawString(72, height - 72, "TheWescan - Vulnerability Report")
    c.setFont("Helvetica", 12)
    c.drawString(72, height - 100, f"Target: {job.get('target', '-')}")
    c.drawString(72, height - 116, f"Status: {job.get('status', '-')}")
    c.drawString(72, height - 132, f"Total findings: {len(job.get('findings', []))}")
    c.drawString(72, height - 160, "Note: This report contains evidence captured during automated scanning on lab target only.")
    c.showPage()

    # Executive summary
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, height - 72, "Executive Summary")
    c.setFont("Helvetica", 11)
    y = height - 100
    c.drawString(72, y, f"Target: {job.get('target', '-')}")
    y -= 16
    c.drawString(72, y, f"Scan status: {job.get('status', '-')}")
    y -= 24
    c.drawString(72, y, f"Total findings: {len(job.get('findings', []))}")
    y -= 24

    # List by severity
    counts = {"High":0, "Medium":0, "Low":0}
    for f in job.get("findings", []):
        counts[f.get("severity","Medium")] = counts.get(f.get("severity","Medium"), 0) + 1
    c.drawString(72, y, f"High: {counts['High']}   Medium: {counts['Medium']}   Low: {counts['Low']}")
    c.showPage()

    # Detailed findings
    for idx, f in enumerate(job.get("findings", []), start=1):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, height - 72, f"Finding {idx}: {f.get('vuln_type','')}")
        c.setFont("Helvetica", 11)
        y = height - 100
        c.drawString(72, y, f"URL: {f.get('url','-')}")
        y -= 14
        c.drawString(72, y, f"Parameter: {f.get('param','-')}")
        y -= 14
        c.drawString(72, y, f"Severity: {f.get('severity','Medium')}")
        y -= 18

        # PoC (payload)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(72, y, "PoC / Payload:")
        y -= 14
        c.setFont("Courier", 9)
        payload_text = str(f.get("payload","-"))
        for line in chunk_text(payload_text, 80):
            c.drawString(80, y, line)
            y -= 12
            if y < 72:
                c.showPage()
                y = height - 72

        y -= 8
        # Evidence snippet
        c.setFont("Helvetica-Bold", 12)
        c.drawString(72, y, "Evidence (snippet):")
        y -= 14
        c.setFont("Courier", 8)
        evidence_text = str(f.get("evidence","-"))
        for line in chunk_text(evidence_text, 100):
            c.drawString(76, y, line)
            y -= 10
            if y < 72:
                c.showPage()
                y = height - 72

        y -= 8
        # Mitigation
        c.setFont("Helvetica-Bold", 12)
        c.drawString(72, y, "Suggested Mitigation:")
        y -= 14
        c.setFont("Helvetica", 10)
        mitig = MITIGATIONS.get(f.get("vuln_type",""), "Review application logic and validate inputs.")
        for line in chunk_text(mitig, 90):
            c.drawString(76, y, line)
            y -= 12
            if y < 72:
                c.showPage()
                y = height - 72

        c.showPage()

    c.save()


def chunk_text(text, width):
    """Yield wrapped lines for PDF rendering (simple)."""
    words = str(text).split()
    line = ""
    for w in words:
        if len(line) + 1 + len(w) > width:
            yield line
            line = w
        else:
            if line:
                line += " " + w
            else:
                line = w
    if line:
        yield line
