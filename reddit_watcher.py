#!/usr/bin/env python3
import requests, json, os, time, logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
TO_EMAIL = "tim@harborprivacy.com"
FROM_EMAIL = "info@mail.harborprivacy.com"
SEEN_FILE = "/var/log/harbor-reddit-seen.json"

RSS_FEEDS = [
    "https://www.reddit.com/r/daddit/search.rss?q=parental+controls&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/daddit/search.rss?q=block+internet&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/Mommit/search.rss?q=parental+controls&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/parenting/search.rss?q=internet+filter&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/parenting/search.rss?q=parental+controls&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/HomeNetworking/search.rss?q=block+ads&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/HomeNetworking/search.rss?q=parental+controls&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/privacy/search.rss?q=DNS+privacy&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/pihole/search.rss?q=alternative&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/pihole/search.rss?q=cloud&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/parentalcontrols/new.rss",
    "https://www.reddit.com/r/techsupport/search.rss?q=block+ads+router&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/techsupport/search.rss?q=parental+controls+router&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/networking/search.rss?q=block+ads&sort=new&restrict_sr=1",
]

TITLE_KEYWORDS = [
    "parental control", "block ads", "content filter", "dns filter",
    "kids internet", "block youtube", "block websites", "isp tracking",
    "pihole", "circle", "family protection", "screen time",
    "block adult", "internet filter", "router block", "dns privacy",
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; HarborPrivacy/1.0)"}

def load_seen():
    try:
        if os.path.exists(SEEN_FILE):
            return set(json.loads(open(SEEN_FILE).read()))
    except:
        pass
    return set()

def save_seen(seen):
    open(SEEN_FILE, "w").write(json.dumps(list(seen)[-1000:]))

def fetch_rss(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        if not r.ok:
            return []
        root = ET.fromstring(r.text)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        posts = []
        for entry in root.findall("atom:entry", ns):
            title = entry.findtext("atom:title", "", ns).strip()
            link_el = entry.find("atom:link", ns)
            link = link_el.get("href", "") if link_el is not None else ""
            post_id = entry.findtext("atom:id", "", ns).strip()
            category = entry.find("atom:category", ns)
            subreddit = category.get("term", "") if category is not None else ""
            updated = entry.findtext("atom:updated", "", ns).strip()
            if title and link and post_id:
                posts.append({"title": title, "link": link, "id": post_id, "subreddit": subreddit, "feed": url, "updated": updated})
        return posts
    except Exception as e:
        log.error(f"RSS error {url}: {e}")
        return []

def is_relevant(post):
    title = post.get("title", "").lower()
    if not any(kw in title for kw in TITLE_KEYWORDS):
        return False
    # Filter posts older than 48 hours
    updated = post.get("updated", "")
    if updated:
        try:
            post_time = datetime.fromisoformat(updated.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) - post_time > timedelta(hours=48):
                return False
        except:
            pass
    return True

def is_recent(post_id):
    # Reddit post IDs are base36 encoded timestamps
    # We filter in the feed fetch instead via updated field
    return True

def send_email(posts):
    rows = ""
    for p in posts:
        rows += f"""
        <tr>
          <td style="padding:12px;border-bottom:1px solid #1e2a2d;">
            <a href="{p['link']}" style="color:#00e5c0;font-family:monospace;font-size:13px;text-decoration:none;">{p['title']}</a><br>
            <span style="color:#6b8a87;font-size:11px;font-family:monospace;">r/{p['subreddit']}</span>
          </td>
        </tr>"""

    html = f"""
    <div style="background:#0a0e0f;padding:32px;font-family:sans-serif;">
      <div style="max-width:600px;margin:0 auto;">
        <p style="font-family:monospace;font-size:12px;color:#00e5c0;letter-spacing:0.2em;">HARBOR PRIVACY</p>
        <h2 style="color:#e8f0ef;font-size:20px;margin-bottom:8px;">Reddit Leads — {datetime.now().strftime("%b %d, %Y %I:%M %p")}</h2>
        <p style="color:#6b8a87;font-size:13px;margin-bottom:24px;">{len(posts)} new posts matching your keywords</p>
        <table style="width:100%;border-collapse:collapse;border:1px solid #1e2a2d;">
          {rows}
        </table>
        <p style="color:#6b8a87;font-size:11px;font-family:monospace;margin-top:24px;">Reply naturally as a dad who solved this problem. No pitching.</p>
      </div>
    </div>"""

    try:
        r = requests.post("https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": FROM_EMAIL, "to": TO_EMAIL, "subject": f"Reddit Leads: {len(posts)} new posts", "html": html},
            timeout=10)
        log.info(f"Email sent: {r.status_code}")
    except Exception as e:
        log.error(f"Email error: {e}")

def main():
    seen = load_seen()
    new_posts = []

    for feed_url in RSS_FEEDS:
        posts = fetch_rss(feed_url)
        for p in posts:
            if p["id"] not in seen:
                seen.add(p["id"])
                if is_relevant(p) and is_recent(p["id"]):
                    new_posts.append(p)
        time.sleep(2)

    save_seen(seen)
    log.info(f"Found {len(new_posts)} relevant new posts")

    if new_posts:
        send_email(new_posts)
    else:
        log.info("No relevant posts, no email sent")

if __name__ == "__main__":
    main()
