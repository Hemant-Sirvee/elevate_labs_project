# app.py — FINAL WORKING VERSION

import os
import threading
from datetime import datetime
from django import db, urls
from flask import (
    Flask, render_template, request, redirect,
    url_for, jsonify, send_file, flash
)
from models import init_db, SessionLocal, ScanJob, Finding, Subdomain

# Scanner modules
from scanner.crawler import discover_forms_and_links
from scanner.xss import test_reflected_xss
from scanner.sqli import test_sqli_on_param
from scanner.lfi import test_lfi_on_param
from scanner.xxe import test_xxe_on_endpoint
from scanner.subdomain import discover_subdomains
from scanner.report import create_pdf_report
from scanner.js_endpoints import find_js_and_extract
from scanner.json_scan import test_json_endpoint


# Initialize the database
init_db()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "devkey")


# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def append_log(db, job_obj, message):
    """Append timestamped logs."""
    msg = f"[{datetime.utcnow().isoformat()}] {message}"
    job_obj.logs = (job_obj.logs or "") + msg + "\n"
    db.add(job_obj)
    db.commit()


def add_finding(db, job_obj, vuln_type, url, param, payload, evidence, severity="High"):
    """Insert a new finding"""
    f = Finding(
        scanjob_id=job_obj.id,
        vuln_type=vuln_type,
        url=url,
        param=param,
        payload=payload,
        evidence=evidence,
        severity=severity
    )
    db.add(f)
    db.commit()
    return f

# Discover API endpoints from scripts on this page
api_endpoints = find_js_and_extract(urls, session=None)
for api in api_endpoints:
    append_log(db, job, f"Found API endpoint (from JS): {api}")
    # run JSON tests
    jfinds = test_json_endpoint(api)
    for jf in jfinds:
        key = ("API", api, str(jf.get("payload")))
        if key not in seen:
            seen.add(key)
            add_finding(db, job, "API-JSON", api, None, str(jf.get("payload")), jf.get("evidence"), severity="High")
            append_log(db, job, f"API JSON finding at {api} type {jf.get('type')}")




def add_subdomain(db, job_obj, hostname, ip_list, status="active"):
    ip = ", ".join(ip_list) if ip_list else None
    s = Subdomain(
        scanjob_id=job_obj.id,
        hostname=hostname,
        ip=ip,
        status=status
    )
    db.add(s)
    db.commit()
    return s


# ---------------------------------------------------------
# MAIN SCAN ROUTE (JSON SWITCH SUPPORT)
# ---------------------------------------------------------

@app.route("/scan/<int:job_id>")
def scan(job_id):
    """
    If ?_json=1 → return JSON findings/subdomains
    Else → return HTML
    """
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()

    if not job:
        db.close()
        return "Job not found", 404

    findings = db.query(Finding).filter(Finding.scanjob_id == job_id).order_by(Finding.created_at).all()
    subs = db.query(Subdomain).filter(Subdomain.scanjob_id == job_id).order_by(Subdomain.created_at).all()

    # JSON mode for frontend
    if request.args.get("_json") == "1":
        def to_dict(obj):
            return {
                "id": obj.id,
                "vuln_type": getattr(obj, "vuln_type", ""),
                "url": getattr(obj, "url", ""),
                "param": getattr(obj, "param", ""),
                "payload": getattr(obj, "payload", ""),
                "evidence": getattr(obj, "evidence", "")[:900],
                "severity": getattr(obj, "severity", ""),
                "created_at": obj.created_at.isoformat() if obj.created_at else ""
            }

        subs_list = [{
            "id": s.id,
            "hostname": s.hostname,
            "ip": s.ip,
            "created_at": s.created_at.isoformat() if s.created_at else ""
        } for s in subs]

        findings_list = [to_dict(f) for f in findings]

        db.close()
        return jsonify({
            "job": {
                "id": job.id,
                "target": job.target,
                "status": job.status
            },
            "subdomains": subs_list,
            "findings": findings_list
        })

    # Normal HTML render
    job.findings = findings
    job.subdomains = subs
    db.close()
    return render_template("scan.html", job=job)


# ---------------------------------------------------------
# START SCAN
# ---------------------------------------------------------

@app.route("/start-scan", methods=["POST"])
def start_scan():
    target = request.form.get("target")
    depth = int(request.form.get("depth", 1))
    consent = request.form.get("consent")

    if not target or not consent:
        flash("Please provide target URL & agree to lab-only scanning.")
        return redirect(url_for("index"))

    db = SessionLocal()
    job = ScanJob(
        target=target,
        profile="default",
        status="queued",
        logs=""
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    db.close()

    # background thread
    t = threading.Thread(target=run_scan, args=(job.id, depth), daemon=True)
    t.start()

    return redirect(url_for("scan", job_id=job.id))


# ---------------------------------------------------------
# STATUS API (used by JS poller)
# ---------------------------------------------------------

@app.route("/scan/<int:job_id>/status")
def scan_status(job_id):
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()

    if not job:
        db.close()
        return jsonify({"error": "not found"}), 404

    findings_count = db.query(Finding).filter(Finding.scanjob_id == job_id).count()

    resp = {
        "status": job.status,
        "findings_count": findings_count,
        "logs": (job.logs or "").splitlines()[-300:],   # last 300 lines
        "show_findings": job.status in ("finished", "error")
    }

    db.close()
    return jsonify(resp)


# ---------------------------------------------------------
# DOWNLOAD PDF REPORT
# ---------------------------------------------------------

@app.route("/scan/<int:job_id>/download")
def scan_download(job_id):
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()

    if not job:
        db.close()
        return "Job not found", 404

    findings = db.query(Finding).filter(Finding.scanjob_id == job_id).all()

    job_dict = {
        "target": job.target,
        "status": job.status,
        "findings": [{
            "vuln_type": f.vuln_type,
            "url": f.url,
            "param": f.param,
            "payload": f.payload,
            "evidence": f.evidence
        } for f in findings]
    }

    pdf_path = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        f"thewescan_report_{job_id}.pdf"
    )

    create_pdf_report(pdf_path, job_dict)
    db.close()

    return send_file(pdf_path, as_attachment=True)


# ---------------------------------------------------------
# SCAN ENGINE (MAIN LOGIC)
# ---------------------------------------------------------

def run_scan(job_id, depth=1):
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        db.close()
        return

    # Deduplication set
    seen = set()

    try:
        job.status = "running"
        job.logs = ""
        db.add(job)
        db.commit()

        append_log(db, job, f"Scan started for {job.target}")

        # Crawl
        pages = discover_forms_and_links(
            job.target,
            max_depth=depth,
            logger=lambda m: append_log(db, job, m)
        )
        append_log(db, job, f"Found {len(pages)} pages")

        # Subdomains
        append_log(db, job, "Starting subdomain discovery")
        subs = discover_subdomains(
            job.target,
            logger=lambda m: append_log(db, job, m)
        )
        for s in subs:
            add_subdomain(db, job, s["hostname"], s.get("ips", []))
            append_log(db, job, f"Subdomain {s['hostname']} -> {s.get('ips')}")

        # Vulnerability tests
        for p in pages:
            url = p["url"]
            append_log(db, job, f"Testing: {url}")

            forms = p.get("forms", [])
            for form in forms:

                # XSS
                x = test_reflected_xss(form)
                if x:
                    key = ("XSS", url, x["param"], x["payload"])
                    if key not in seen:
                        seen.add(key)
                        add_finding(
                            db, job, "XSS", url,
                            x["param"], x["payload"], x["evidence"]
                        )
                        append_log(db, job, f"XSS → {url} :: {x['param']}")

                # SQLi + LFI
                for inp in form["inputs"]:
                    if inp.get("type") in ("text", "", "search"):

                        # SQLi
                        sqli = test_sqli_on_param(url, inp["name"])
                        if sqli:
                            key = ("SQLi", url, inp["name"], sqli["payload"])
                            if key not in seen:
                                seen.add(key)
                                add_finding(
                                    db, job, "SQLi", url,
                                    inp["name"], sqli["payload"], sqli["evidence"]
                                )
                                append_log(db, job, f"SQLi → {url} :: {inp['name']}")

                        # LFI
                        lfi = test_lfi_on_param(url, inp["name"])
                        if lfi:
                            key = ("LFI", url, inp["name"], lfi["payload"])
                            if key not in seen:
                                seen.add(key)
                                add_finding(
                                    db, job, "LFI", url,
                                    inp["name"], lfi["payload"], lfi["evidence"]
                                )
                                append_log(db, job, f"LFI → {url} :: {inp['name']}")

            # XXE heuristics
            if url.lower().endswith((".xml", "/xml", "/api")) or "xml" in url.lower():
                xxe = test_xxe_on_endpoint(url)
                if xxe:
                    key = ("XXE", url, None, xxe["payload"])
                    if key not in seen:
                        seen.add(key)
                        add_finding(
                            db, job, "XXE", url,
                            None, xxe["payload"], xxe["evidence"]
                        )
                        append_log(db, job, f"XXE → {url}")

        job.status = "finished"
        job.finished_at = datetime.utcnow()
        append_log(db, job, "Scan finished")

    except Exception as e:
        job.status = "error"
        append_log(db, job, f"ERROR: {e}")

    finally:
        db.add(job)
        db.commit()
        db.close()


# ---------------------------------------------------------
# INDEX
# ---------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------
# RUN
# ---------------------------------------------------------

if __name__ == "__main__":
    # Works perfectly in Windows
    app.run(host="127.0.0.1", port=5000, debug=True)
