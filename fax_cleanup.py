#!/usr/bin/env python3
"""Backstop sweep: delete fax uploads and merged PDFs older than 2 hours.
Runs hourly via cron. The Telnyx webhook handles immediate delete-on-delivery;
this catches anything orphaned (never paid, missed webhook, etc).
"""
import sqlite3, os
from pathlib import Path
from datetime import datetime, timedelta

DB_PATH = "/home/ubuntu/harbor-fax.db"
UPLOAD_DIR = Path("/tmp/harbor-fax-uploads")
MAX_AGE_HOURS = 2

cutoff = (datetime.utcnow() - timedelta(hours=MAX_AGE_HOURS)).isoformat()
removed_files = 0
removed_merged = 0

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

for row in conn.execute("SELECT token, file_path FROM fax_files WHERE created_at < ?", (cutoff,)).fetchall():
    fp = row["file_path"]
    if fp and Path(fp).exists():
        try:
            Path(fp).unlink()
            removed_files += 1
        except Exception:
            pass
    conn.execute("DELETE FROM fax_files WHERE token=?", (row["token"],))

for row in conn.execute("SELECT token, merged_pdf FROM fax_orders WHERE created_at < ? AND merged_pdf IS NOT NULL AND merged_pdf != ''", (cutoff,)).fetchall():
    mp = row["merged_pdf"]
    if mp and Path(mp).exists():
        try:
            Path(mp).unlink()
            removed_merged += 1
        except Exception:
            pass
    conn.execute("UPDATE fax_orders SET merged_pdf='' WHERE token=?", (row["token"],))

conn.commit()
conn.close()

# Belt-and-suspenders: any stray file in upload dir older than 2h
cutoff_ts = (datetime.utcnow() - timedelta(hours=MAX_AGE_HOURS)).timestamp()
stray = 0
if UPLOAD_DIR.exists():
    for f in UPLOAD_DIR.iterdir():
        try:
            if f.is_file() and f.stat().st_mtime < cutoff_ts:
                f.unlink()
                stray += 1
        except Exception:
            pass

print(f"fax_cleanup: removed {removed_files} upload(s), {removed_merged} merged PDF(s), {stray} stray file(s)")

