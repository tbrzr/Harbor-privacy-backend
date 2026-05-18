"""
Admin routes for fax.py. Registered onto the existing Flask app.

import this module after `app = Flask(__name__)` is created in fax.py and call
    register_fax_admin(app, db_path=DB_PATH, file_dir=FAX_FILE_DIR)
"""
import os
import json
import sqlite3
import time
from pathlib import Path

from flask import (current_app, jsonify, redirect, render_template, request,
                   session)

from admin_common import (init_admin_auth, admin_required, audit_log,
                          read_audit, csrf_token)


def _conn(db_path):
    c = sqlite3.connect(db_path)
    c.row_factory = sqlite3.Row
    return c


def _ensure_admin_tables(db_path):
    with _conn(db_path) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS admin_setting (
            key   TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS admin_marked (
            token TEXT PRIMARY KEY,
            reason TEXT,
            at TEXT
        )""")
        c.commit()


def _get_setting(db_path, key, default=None):
    with _conn(db_path) as c:
        r = c.execute("SELECT value FROM admin_setting WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def _set_setting(db_path, key, value):
    with _conn(db_path) as c:
        c.execute("""INSERT INTO admin_setting (key,value,updated_at)
                     VALUES (?,?,?)
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                  (key, str(value) if value is not None else None,
                   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        c.commit()


def get_bool(db_path, key, default=False):
    v = _get_setting(db_path, key)
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "yes", "on")


def register_fax_admin(app, db_path, file_dir):
    audit_path = init_admin_auth(app, app_name="fax")
    _ensure_admin_tables(db_path)

    def _audit(action, target_type=None, target_id=None, payload=None):
        audit_log(audit_path, session.get("admin_email"),
                  action, target_type, target_id, payload)

    def _stats():
        with _conn(db_path) as c:
            counts = {r["status"] or "?": r["n"]
                      for r in c.execute("SELECT status, COUNT(*) AS n FROM fax_orders GROUP BY status")}
            total_orders = c.execute("SELECT COUNT(*) AS n FROM fax_orders").fetchone()["n"]
            total_files  = c.execute("SELECT COUNT(*) AS n FROM fax_files").fetchone()["n"]
            sum_amt = c.execute("SELECT COALESCE(SUM(amount),0) AS s FROM fax_orders WHERE status IN ('paid','sent')").fetchone()["s"]
        # disk usage of fax_files dir
        try:
            disk_bytes = sum(p.stat().st_size for p in Path(file_dir).glob("**/*") if p.is_file())
        except Exception:
            disk_bytes = 0
        return {
            "counts": counts, "total_orders": total_orders,
            "total_files": total_files, "sum_amount_cents": sum_amt,
            "disk_bytes": disk_bytes,
        }

    @app.route("/admin", methods=["GET"])
    @admin_required
    def admin_home():
        status = (request.args.get("status") or "").strip()
        q = (request.args.get("q") or "").strip()
        params, where = [], []
        if status:
            where.append("status = ?"); params.append(status)
        if q:
            where.append("(fax_number LIKE ? OR to_name LIKE ? OR email LIKE ? OR token LIKE ?)")
            like = f"%{q}%"
            params += [like, like, like, like]
        sql = "SELECT * FROM fax_orders"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT 200"
        with _conn(db_path) as c:
            orders = [dict(r) for r in c.execute(sql, params).fetchall()]
        flags = {
            "orders_paused": get_bool(db_path, "orders_paused", False),
            "banner":        _get_setting(db_path, "banner", ""),
        }
        return render_template("fax_admin.html",
                               tab="orders", orders=orders, status=status, q=q,
                               flags=flags, stats=_stats(),
                               audit=read_audit(audit_path, 50))

    @app.route("/admin/order/<token>", methods=["GET"])
    @admin_required
    def admin_order(token):
        with _conn(db_path) as c:
            order = c.execute("SELECT * FROM fax_orders WHERE token=?", (token,)).fetchone()
            if not order:
                return ("not found", 404)
            order = dict(order)
            file_rows = []
            try:
                tokens = json.loads(order.get("file_tokens") or "[]")
            except Exception:
                tokens = []
            for ft in tokens:
                r = c.execute("SELECT * FROM fax_files WHERE token=?", (ft,)).fetchone()
                if r:
                    d = dict(r)
                    p = Path(d.get("file_path") or "")
                    d["exists"] = p.exists()
                    d["size"]   = p.stat().st_size if p.exists() else 0
                    file_rows.append(d)
        return render_template("fax_admin.html", tab="order_view",
                               order=order, file_rows=file_rows,
                               stats=_stats(),
                               flags={"orders_paused": get_bool(db_path,"orders_paused",False),
                                      "banner": _get_setting(db_path,"banner","")})

    @app.route("/admin/order/<token>/delete", methods=["POST"])
    @admin_required
    def admin_order_delete(token):
        removed_files = 0
        with _conn(db_path) as c:
            row = c.execute("SELECT file_tokens, merged_pdf FROM fax_orders WHERE token=?", (token,)).fetchone()
            if not row:
                return jsonify({"error": "not found"}), 404
            try:
                file_tokens = json.loads(row["file_tokens"] or "[]")
            except Exception:
                file_tokens = []
            for ft in file_tokens:
                f = c.execute("SELECT file_path FROM fax_files WHERE token=?", (ft,)).fetchone()
                if f and f["file_path"]:
                    try:
                        Path(f["file_path"]).unlink(missing_ok=True); removed_files += 1
                    except Exception:
                        pass
                c.execute("DELETE FROM fax_files WHERE token=?", (ft,))
            merged = row["merged_pdf"]
            if merged:
                try:
                    Path(merged).unlink(missing_ok=True); removed_files += 1
                except Exception:
                    pass
            c.execute("DELETE FROM fax_orders WHERE token=?", (token,))
            c.commit()
        _audit("order.delete", "order", token, {"files_removed": removed_files})
        return redirect("/admin")

    @app.route("/admin/sweep", methods=["POST"])
    @admin_required
    def admin_sweep():
        days = int(request.form.get("days") or "30")
        cutoff_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                   time.gmtime(time.time() - days * 86400))
        removed_files = 0
        removed_orders = 0
        with _conn(db_path) as c:
            old = c.execute("""SELECT token, file_tokens, merged_pdf FROM fax_orders
                              WHERE status IN ('sent','failed','cancelled','expired')
                                AND created_at < ?""", (cutoff_iso,)).fetchall()
            for r in old:
                try:
                    fts = json.loads(r["file_tokens"] or "[]")
                except Exception:
                    fts = []
                for ft in fts:
                    f = c.execute("SELECT file_path FROM fax_files WHERE token=?", (ft,)).fetchone()
                    if f and f["file_path"]:
                        try:
                            Path(f["file_path"]).unlink(missing_ok=True); removed_files += 1
                        except Exception:
                            pass
                    c.execute("DELETE FROM fax_files WHERE token=?", (ft,))
                if r["merged_pdf"]:
                    try:
                        Path(r["merged_pdf"]).unlink(missing_ok=True); removed_files += 1
                    except Exception:
                        pass
                c.execute("DELETE FROM fax_orders WHERE token=?", (r["token"],))
                removed_orders += 1
            # orphan fax_files (no referencing order) older than 7 days
            orph_cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(time.time() - 7 * 86400))
            orphans = c.execute("""SELECT f.token, f.file_path
                FROM fax_files f
                LEFT JOIN fax_orders o ON instr(IFNULL(o.file_tokens,''), f.token) > 0
                WHERE o.token IS NULL AND f.created_at < ?""", (orph_cutoff,)).fetchall()
            for o in orphans:
                if o["file_path"]:
                    try:
                        Path(o["file_path"]).unlink(missing_ok=True); removed_files += 1
                    except Exception:
                        pass
                c.execute("DELETE FROM fax_files WHERE token=?", (o["token"],))
            c.commit()
        payload = {"days": days, "orders_removed": removed_orders,
                   "files_removed": removed_files, "orphans": len(orphans)}
        _audit("sweep", "fax", None, payload)
        return jsonify({"ok": True, **payload})

    @app.route("/admin/flags", methods=["POST"])
    @admin_required
    def admin_flags():
        orders_paused = "1" if request.form.get("orders_paused") == "on" else "0"
        banner = (request.form.get("banner") or "").strip()
        _set_setting(db_path, "orders_paused", orders_paused)
        _set_setting(db_path, "banner", banner)
        _audit("flags", "system", None, {"orders_paused": orders_paused, "banner": banner[:80]})
        return redirect("/admin")
