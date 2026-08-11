#!/usr/bin/env python3
"""One-time manual backfill: same feeds/keywords as reddit_watcher.py, but a 30-day
freshness window instead of the production 48h cutoff, so the /reddit-leads dashboard
has real content to review. Does NOT touch SEEN_FILE, so it has no effect on the
normal automated cron cycle.
"""
import time
from datetime import datetime, timezone, timedelta
import reddit_watcher as rw

MAX_AGE_DAYS = 90
MAX_LEADS = 8

def is_relevant_backfill(post):
    title = post.get("title", "").lower()
    if not any(kw in title for kw in rw.TITLE_KEYWORDS):
        return False
    updated = post.get("updated", "")
    if updated:
        try:
            post_time = datetime.fromisoformat(updated.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) - post_time > timedelta(days=MAX_AGE_DAYS):
                return False
        except Exception:
            pass
    return True

def main():
    existing_ids = {l["id"] for l in rw.load_leads().get("leads", [])}

    matches = []
    seen_links = set()
    for feed_url in rw.RSS_FEEDS:
        posts = rw.fetch_rss(feed_url)
        for p in posts:
            if p["link"] in seen_links or p["id"] in existing_ids:
                continue
            if is_relevant_backfill(p):
                seen_links.add(p["link"])
                matches.append(p)
        time.sleep(8)

    matches.sort(key=lambda p: p.get("updated", ""), reverse=True)
    matches = matches[:MAX_LEADS]
    print(f"Backfilling {len(matches)} new leads (<= {MAX_AGE_DAYS}d old, {len(existing_ids)} already in file skipped)")
    if matches:
        rw.add_leads(matches)
    for m in matches:
        print(f"  r/{m['subreddit']}: {m['title']}")

if __name__ == "__main__":
    main()
