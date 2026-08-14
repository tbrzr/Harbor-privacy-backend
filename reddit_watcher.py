#!/usr/bin/env python3
import requests, json, os, time, logging, subprocess, tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
TO_EMAIL = "tim@harborprivacy.com"
FROM_EMAIL = "info@mail.harborprivacy.com"
SEEN_FILE = "/home/ubuntu/harbor-backend/harbor-reddit-seen.json"
LEADS_FILE = "/home/ubuntu/harbor-reddit-leads.json"

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_URL = (
    f"https://gateway.ai.cloudflare.com/v1/{os.environ.get('CF_ACCOUNT_ID')}/"
    f"{os.environ.get('CF_AI_GATEWAY', 'harbor')}/anthropic/v1/messages"
    if os.environ.get("CF_ACCOUNT_ID") else "https://api.anthropic.com/v1/messages"
)

NTFY = "https://ntfy.harborprivacy.com/harbor-alerts"
NTFY_AUTH = "Basic aGFyYm9ydGltOlBlbmVsMHBlIUAhQCFA"

PI_PROXY = "socks5h://127.0.0.1:1080"

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
    "https://www.reddit.com/r/HomeNetworking/search.rss?q=adguard&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/HomeNetworking/search.rss?q=nextdns&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/pihole/search.rss?q=adguard&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/AskParents/search.rss?q=screen+time&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/AskParents/search.rss?q=block+youtube&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/Ubiquiti/search.rss?q=parental+controls&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/openwrt/search.rss?q=parental+controls&sort=new&restrict_sr=1",
    "https://www.reddit.com/r/HomeNetworking/search.rss?q=guest+wifi+kids&sort=new&restrict_sr=1",
]

TITLE_KEYWORDS = [
    "parental control", "block ads", "content filter", "dns filter",
    "kids internet", "block youtube", "block websites", "isp tracking",
    "pihole", "pi-hole", "circle", "family protection", "screen time",
    "block adult", "internet filter", "router block", "dns privacy",
    "adguard", "nextdns", "dns blocklist", "block tiktok", "kid safe",
    "kid-safe", "family wifi", "guest wifi kids", "network wide ad",
    "network-wide ad", "block porn", "content blocker", "wifi parental",
    "router parental", "vpn kill switch parent", "screen time app",
    "isp spying", "dns encryption", "encrypted dns",
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
    try:
        open(SEEN_FILE, "w").write(json.dumps(list(seen)[-1000:]))
    except Exception as e:
        log.error(f"save_seen error: {e}")

def fetch_rss(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15,
                          proxies={"http": PI_PROXY, "https": PI_PROXY})
        if not r.ok:
            log.warning(f"RSS http {r.status_code} {url} (reset={r.headers.get('x-ratelimit-reset','?')}s)")
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

DRAFT_PROMPT = """A Reddit post titled "{title}" was just posted in r/{subreddit}.

Write a short reply Tim (a dad who runs Harbor Privacy, a DNS-level ad/tracker/parental-control
filtering service, $1.99/mo, open-source-verifiable, works on any router) could post.

Rules:
- 2-4 sentences, plain text, no markdown, no quotes around it, no em dash.
- Sound like a real Reddit comment from a person, not marketing copy. No superlatives
  ("game changer", "amazing"), no exclamation points, no "I've been there!" filler.
- Only mention Harbor Privacy if it is a genuinely direct answer to what they asked, and mention
  it once, factually, alongside AdGuard Home as the free self-hosted alternative (never claim
  Harbor is the only option).
- If the post is a narrow troubleshooting question about a specific product bug (not "how do I
  solve this problem in general"), do NOT pitch anything. Just write a genuinely helpful,
  on-topic reply with no product mention, or reply with exactly NONE if you have nothing
  substantive to add.
- Never claim "no signup required" or make any claim you cannot verify from the post title alone.

Reply:"""

def draft_reply(post):
    if not ANTHROPIC_API_KEY:
        return None
    prompt = DRAFT_PROMPT.format(title=post["title"], subreddit=post["subreddit"])
    try:
        r = requests.post(ANTHROPIC_URL,
            headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": "claude-sonnet-5", "max_tokens": 300,
                  "thinking": {"type": "disabled"},
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        if not r.ok:
            log.error(f"draft_reply http {r.status_code}: {r.text[:200]}")
            return None
        blocks = r.json().get("content", [])
        text = next((b["text"] for b in blocks if b.get("type") == "text"), "").strip()
        return None if not text or text.upper() == "NONE" else text
    except Exception as e:
        log.error(f"draft_reply error: {e}")
        return None

def load_leads():
    try:
        with open(LEADS_FILE) as f:
            return json.load(f)
    except Exception:
        return {"version": 1, "leads": []}

def save_leads(data):
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(LEADS_FILE), prefix=".reddit-leads-", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, LEADS_FILE)
    except Exception as e:
        if tmp:
            try: os.unlink(tmp)
            except Exception: pass
        log.error(f"save_leads error: {e}")

def add_leads(posts):
    data = load_leads()
    now = datetime.now(timezone.utc).isoformat()
    for p in posts:
        data["leads"].append({
            "id": p["id"],
            "subreddit": p["subreddit"],
            "title": p["title"],
            "link": p["link"],
            "draft": draft_reply(p),
            "status": "new",
            "found_at": now,
        })
    data["leads"] = data["leads"][-500:]
    save_leads(data)

def send_email(posts):
    rows = ""
    for p in posts:
        rows += f"""
        <tr>
          <td style="padding:12px;border-bottom:1px solid #1e2a2d;">
            <a href="{p['link']}" style="color:#1f5d6b;font-family:monospace;font-size:13px;text-decoration:none;">{p['title']}</a><br>
            <span style="color:#6b7a72;font-size:11px;font-family:monospace;">r/{p['subreddit']}</span>
          </td>
        </tr>"""

    html = f"""
    <div style="background:#fbf7f0;padding:32px;font-family:sans-serif;">
      <div style="max-width:600px;margin:0 auto;">
        <p style="font-family:monospace;font-size:12px;color:#1f5d6b;letter-spacing:0.2em;">HARBOR PRIVACY</p>
        <h2 style="color:#1a2420;font-size:20px;margin-bottom:8px;">Reddit Leads — {datetime.now().strftime("%b %d, %Y %I:%M %p")}</h2>
        <p style="color:#6b7a72;font-size:13px;margin-bottom:24px;">{len(posts)} new posts matching your keywords</p>
        <table style="width:100%;border-collapse:collapse;border:1px solid #e6dfd2;">
          {rows}
        </table>
        <p style="color:#6b7a72;font-size:11px;font-family:monospace;margin-top:24px;">Reply naturally as a dad who solved this problem. No pitching.</p>
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

def send_ntfy(posts):
    lines = "\n".join(f"r/{p['subreddit']}: {p['title']}" for p in posts[:5])
    if len(posts) > 5:
        lines += f"\n+{len(posts) - 5} more"
    try:
        r = subprocess.run(
            ["curl", "-s", "-X", "POST", NTFY,
             "-H", f"Authorization: {NTFY_AUTH}",
             "-H", "Title: Reddit Leads",
             "-H", f"Click: {posts[0]['link']}",
             "-H", "Tags: mag",
             "-d", lines],
            timeout=10, capture_output=True, text=True)
        log.info(f"ntfy sent: {r.returncode}")
    except Exception as e:
        log.error(f"ntfy error: {e}")

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
        time.sleep(45)

    save_seen(seen)
    log.info(f"Found {len(new_posts)} relevant new posts")

    if new_posts:
        add_leads(new_posts)
        send_email(new_posts)
        send_ntfy(new_posts)
    else:
        log.info("No relevant posts, no alert sent")

if __name__ == "__main__":
    main()
