"""
Admin routes for coverletter.py (Career). Jobs live in JSON.
"""
import json
import os
import time
from pathlib import Path

from flask import jsonify, redirect, render_template, request, session

from admin_common import (init_admin_auth, admin_required, audit_log,
                          read_audit, csrf_token)

JOBS_FILE = "/var/log/coverletter-jobs.json"
SETTINGS_FILE = "/var/log/coverletter-admin-settings.json"


def _load_jobs():
    try:
        return json.loads(Path(JOBS_FILE).read_text())
    except Exception:
        return {}


def _save_jobs(jobs):
    Path(JOBS_FILE).write_text(json.dumps(jobs, indent=2))


def _load_settings():
    try:
        return json.loads(Path(SETTINGS_FILE).read_text())
    except Exception:
        return {}


def _save_settings(s):
    Path(SETTINGS_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(SETTINGS_FILE).write_text(json.dumps(s, indent=2))


def _stats(jobs):
    counts = {}
    by_type = {}
    paid = 0
    for j in jobs.values():
        s = j.get("status") or "?"
        counts[s] = counts.get(s, 0) + 1
        t = j.get("type") or "coverletter"
        by_type[t] = by_type.get(t, 0) + 1
        if j.get("paid"):
            paid += 1
    return {"total": len(jobs), "counts": counts, "by_type": by_type, "paid": paid}


def _job_pdf_paths(job_id, job):
    paths = []
    for k in ("pdf_path", "revised_pdf_path", "resume_pdf_path"):
        p = job.get(k)
        if p:
            paths.append(p)
    # Default predictable path even if not stored
    paths.append(f"/tmp/coverletter_{job_id}.pdf")
    return [p for p in paths if p]


def register_career_admin(app):
    audit_path = init_admin_auth(app, app_name="career")

    def _audit(action, target_type=None, target_id=None, payload=None):
        audit_log(audit_path, session.get("admin_email"),
                  action, target_type, target_id, payload)

    @app.route("/admin", methods=["GET"])
    @admin_required
    def admin_home():
        jobs = _load_jobs()
        q = (request.args.get("q") or "").strip().lower()
        status = (request.args.get("status") or "").strip()
        kind = (request.args.get("kind") or "").strip()
        rows = []
        for jid, j in jobs.items():
            if status and (j.get("status") != status):
                continue
            if kind and (j.get("type") != kind):
                continue
            if q:
                blob = " ".join(str(v) for v in (j.get("email",""), j.get("your_name",""),
                                                 j.get("access_code",""), jid)).lower()
                if q not in blob:
                    continue
            rows.append((jid, j))
        rows.sort(key=lambda kv: kv[1].get("created_at", ""), reverse=True)
        rows = rows[:200]
        settings = _load_settings()
        flags = {
            "orders_paused": bool(settings.get("orders_paused")),
            "banner":        settings.get("banner", ""),
        }
        return render_template("career_admin.html",
                               tab="jobs", rows=rows, status=status, kind=kind, q=q,
                               stats=_stats(jobs), flags=flags,
                               audit=read_audit(audit_path, 50))

    @app.route("/admin/job/<job_id>", methods=["GET"])
    @admin_required
    def admin_job(job_id):
        jobs = _load_jobs()
        job = jobs.get(job_id)
        if not job:
            return ("not found", 404)
        existing_pdfs = []
        for p in _job_pdf_paths(job_id, job):
            pp = Path(p)
            if pp.exists():
                existing_pdfs.append({"path": p, "size": pp.stat().st_size})
        return render_template("career_admin.html", tab="job_view",
                               job_id=job_id, job=job, pdfs=existing_pdfs,
                               stats=_stats(jobs),
                               flags=_load_settings(),
                               audit=read_audit(audit_path, 20))

    @app.route("/admin/job/<job_id>/delete", methods=["POST"])
    @admin_required
    def admin_job_delete(job_id):
        jobs = _load_jobs()
        if job_id not in jobs:
            return jsonify({"error": "not found"}), 404
        removed = 0
        for p in _job_pdf_paths(job_id, jobs[job_id]):
            try:
                Path(p).unlink(missing_ok=True); removed += 1
            except Exception:
                pass
        del jobs[job_id]
        _save_jobs(jobs)
        _audit("job.delete", "job", job_id, {"files_removed": removed})
        return redirect("/admin")

    @app.route("/admin/job/<job_id>/resend_code", methods=["POST"])
    @admin_required
    def admin_resend_code(job_id):
        jobs = _load_jobs()
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        email = job.get("email"); code = job.get("access_code")
        if not (email and code):
            return jsonify({"error": "no email or code on file"}), 400
        try:
            import resend
            resend.api_key = os.environ.get("RESEND_API_KEY", "")
            resend.Emails.send({
                "from": "Harbor Career <career@mail.harborprivacy.com>",
                "to": [email],
                "subject": "Your access code",
                "html": f"<p>Access code for your job: <strong style='font-size:1.4rem'>{code}</strong></p>",
            })
            _audit("job.resend_code", "job", job_id, {"email": email})
            return redirect(f"/admin/job/{job_id}")
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/admin/sweep", methods=["POST"])
    @admin_required
    def admin_sweep():
        days = int(request.form.get("days") or "30")
        cutoff = time.time() - days * 86400
        jobs = _load_jobs()
        removed_jobs = 0
        removed_files = 0
        keep = {}
        for jid, j in jobs.items():
            try:
                ts = j.get("created_at", "")
                # accept ISO timestamps or epoch numbers
                age = 0
                if isinstance(ts, str) and ts:
                    try:
                        from datetime import datetime as _dt
                        epoch = _dt.fromisoformat(ts.replace("Z","")).timestamp()
                        age = time.time() - epoch
                    except Exception:
                        age = 0
                elif isinstance(ts, (int, float)):
                    age = time.time() - ts
            except Exception:
                age = 0
            if age and age > days * 86400:
                for p in _job_pdf_paths(jid, j):
                    try:
                        Path(p).unlink(missing_ok=True); removed_files += 1
                    except Exception:
                        pass
                removed_jobs += 1
            else:
                keep[jid] = j
        _save_jobs(keep)
        payload = {"days": days, "removed_jobs": removed_jobs, "removed_files": removed_files}
        _audit("sweep", "career", None, payload)
        return jsonify({"ok": True, **payload})

    @app.route("/admin/flags", methods=["POST"])
    @admin_required
    def admin_flags():
        s = _load_settings()
        s["orders_paused"] = (request.form.get("orders_paused") == "on")
        s["banner"]        = (request.form.get("banner") or "").strip()
        _save_settings(s)
        _audit("flags", "system", None, {"orders_paused": s["orders_paused"], "banner": s["banner"][:80]})
        return redirect("/admin")
