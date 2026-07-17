#!/usr/bin/env python3
"""Generate ONE fresh AI social post, render an on-brand card, add it to the
rotation manifest, and prune old content so nothing accumulates.

Run from a root cron that sources /etc/harbor-dashboard.env (for ANTHROPIC_API_KEY):
  set -a; . /etc/harbor-dashboard.env; set +a; python3 /home/ubuntu/social-refresh.py

Quality gates reject junk before it ever enters the pool; pruning caps the pool
and deletes orphaned image files.
"""
import os, sys, json, time, html, textwrap, subprocess, urllib.request, random
from pathlib import Path
import card_engine

SOCIAL_DIR = Path("/home/ubuntu/harbor-design-system/assets/social")
MANIFEST   = SOCIAL_DIR / "manifest.json"
TIP_BANK   = Path("/home/ubuntu/tip-bank.json")
ASSET_BASE = "https://assets.harborprivacy.com/raw/social"
IMG_JUNK   = Path("/var/www/network/social-images")
MAX_AI     = 24          # cap on AI-generated entries in the pool
JUNK_AGE_D = 14          # delete social-images files older than this many days

# Routes through Cloudflare AI Gateway (cost/latency visibility) when CF_ACCOUNT_ID
# is set in the cron's env; falls back to calling Anthropic directly otherwise.
ANTHROPIC_URL = (
    f"https://gateway.ai.cloudflare.com/v1/{os.environ.get('CF_ACCOUNT_ID')}/"
    f"{os.environ.get('CF_AI_GATEWAY', 'harbor')}/anthropic/v1/messages"
    if os.environ.get("CF_ACCOUNT_ID") else "https://api.anthropic.com/v1/messages"
)

# Stickers are a real product with designed cards + hand-written captions, so the
# rotation serves the pre-rendered posts (make-sticker-posts.py) instead of letting
# the AI invent copy. posts.json is the shared source of truth.
SRC_PER_STICKER = Path("/home/ubuntu/harbor-design-system/assets/stickers/social/per-sticker")
STICKER_POSTS = SRC_PER_STICKER / "posts.json"

BRANDS = {
    "harbor":  ("HARBOR / PRIVACY", "PRIVACY TIP",  "harborprivacy.com",
                "home network privacy, encrypted DNS, ad/tracker blocking, parental controls, ISP tracking, smart-device spying"),
    "career":  ("HARBOR / CAREER",  "CAREER TIP",   "harborprivacy.com/career",
                "privacy-first AI resume and cover-letter tailoring, beating ATS filters, job-search data privacy"),
    "fax":     ("HARBOR / FAX",     "PRIVACY TIP",  "harborprivacy.com/fax",
                "anonymous faxing with no stored copy, HIPAA-friendly sending of medical/legal documents, no account"),
    "booking": ("HARBOR / BOOKING", "BUSINESS TIP", "harborprivacy.com/booking",
                "free appointment scheduling and employee shifts that keep client/staff data private, never sold"),
    "money":   ("HARBOR / MONEY",   "MONEY TIP",    "harborprivacy.com/money",
                "budgeting without sharing your bank login, forwarding receipts/alerts, private alternative to Mint/YNAB"),
    "neighbor":("HARBOR / NEIGHBOR","NETWORK TIP",  "neighbor.harborprivacy.com",
                "self-serve network management for people who share a home or building, each neighbor claims their own VLAN and WiFi password and guest network and device list, "
                "vendor-neutral adapter layer that runs on TP-Link Omada today with UniFi and pfSense next, the operator never sees your traffic only network state, "
                "see-as-you support needs a code you give them, a full live demo with sample data at neighbor-demo.harborprivacy.com"),
    "scan":    ("HARBOR / SCAN",    "PRIVACY TIP",  "scan.harborprivacy.com",
                "finding your name/address/phone/relatives for sale on people-search data brokers like Spokeo Whitepages BeenVerified, "
                "filing automated CCPA opt-outs on your behalf as authorized agent, weekly re-scans because brokers quietly relist you, "
                "verifiable removal receipts not vague status pages, cheaper than DeleteMe and Incogni, "
                "masked email burner addresses that forward to your real inbox so you stop handing the real one to stores and forms, "
                "kill a masked address the day it starts getting spam and you know exactly who leaked it"),
    "burn":    ("HARBOR / BURN",    "PRIVACY TIP",  "burn.harborprivacy.com",
                "sending a password or private message as a self-destructing link that can only be opened once then burns, "
                "end-to-end encrypted in your browser so Harbor never sees the contents, the decryption key lives in the link not on the server, "
                "no account needed, set an expiry, stop pasting passwords into email/Slack/text where they live forever"),
    "stickers":("HARBOR / STICKERS","STICKER DROP", "harborprivacy.etsy.com",
                "die-cut vinyl laptop stickers with privacy slogans like My DNS is mine, I read the privacy policy, and Cookies declined, "
                "weatherproof and matte, now shipping, 4 dollars each or 18 for the pack of eleven, for homelab and privacy people"),
    "playpark":("HARBOR / PLAY PARK","GAME TIP", "harborplay.us",
                "free family-friendly browser games like Word Guess, Word Groups, Trivia, Duck Shoot, Memory, and Spot the Difference, "
                "no account and no ads, good for road trips, waiting rooms, and screen time that is not another ad-tracking app, "
                "Pro is a one-time 4.99 dollar unlock for bonus themes and features, not a subscription, restorable across devices by email, "
                "made by the same team as Harbor Privacy"),
}
# brands where "no account / no signup" claims are FALSE -> reject if present
ACCOUNT_REQUIRED = {"booking", "money", "neighbor", "scan"}

BG="#fbf7f1"; GRID="#e5dfd3"; INK="#1a2420"; MUTE="#6b7a72"; TEAL="#1f5d6b"; TERRA="#c98a52"


def load_manifest():
    return json.loads(MANIFEST.read_text())


def pick_brand(entries):
    """Rotate by least-recently-generated brand to keep coverage even."""
    order = list(BRANDS)
    last = {b: -1 for b in order}
    for i, e in enumerate(entries):
        b = e.get("brand")
        if b in last:
            last[b] = i
    return min(order, key=lambda b: last[b])


def recent_headlines(entries, brand, n=12):
    hs = [e.get("head", "") for e in entries if e.get("brand") == brand and e.get("head")]
    return hs[-n:]


def pick_seed(data, brand):
    """Pick an unused tip-bank seed for this brand; cycle the brand's seeds once
    all are used so the rotation restarts instead of running dry."""
    try:
        bank = json.loads(TIP_BANK.read_text())
    except Exception as e:
        print(f"tip-bank unavailable ({e!r}); falling back to free-invent")
        return None
    seeds = bank.get(brand, [])
    if not seeds:
        return None
    used = set(data.get("used_seeds", []))
    pool = [s for s in seeds if s["id"] not in used]
    if not pool:
        ids = {s["id"] for s in seeds}
        data["used_seeds"] = [u for u in data.get("used_seeds", []) if u not in ids]
        pool = seeds
    return random.choice(pool)


def sticker_entry(data):
    """Pick the next unused sticker (cycling once all are used) and return a ready
    manifest entry built from the pre-rendered image + posts.json caption. No AI,
    no card render. Uses a stable id per slug so re-runs replace rather than pile up,
    which also means prune never has to delete the shared sticker image files."""
    doc = json.loads(STICKER_POSTS.read_text())
    posts = doc["posts"]
    img_base = doc["img_base"].rstrip("/")
    link = doc.get("link", "harborprivacy.com/stickers")

    used = set(data.get("used_stickers", []))
    pool = [p for p in posts if p["slug"] not in used]
    if not pool:                       # exhausted -> restart the cycle
        data["used_stickers"] = []
        pool = posts
    p = random.choice(pool)
    pid = f"sticker-{p['slug']}"

    # The /social/img route serves a LOCAL png from assets/social and only falls
    # back to entry["img"] (login-walled here). So drop a png copy of the square
    # card into SOCIAL_DIR, exactly like the AI path's render_card does.
    src = SRC_PER_STICKER / f"{p['slug']}-square-1080.jpg"
    try:
        from PIL import Image
        im = Image.open(src).convert("RGB")
        im.save(SOCIAL_DIR / f"{pid}.png", "PNG")
        im.save(SOCIAL_DIR / f"{pid}-sq.png", "PNG")   # square preview on the post page
    except Exception as e:
        print(f"sticker_entry: could not stage png for {pid}: {e!r}")

    body = f"{p['caption']}\n\n{link}\n\n{p['hashtags']}"
    entry = {
        "id": pid,
        "category": "Stickers",
        "source": "sticker",
        "brand": "stickers",
        "created": int(time.time()),
        "head": p["head"],
        "hdr": f"STICKERS / {p['head']} -> {link}",
        "img": f"{img_base}/{p['slug']}-square-1080.jpg",
        "link": f"https://{link}",
        "tags": "lightbulb,shield",
        "body": body,
    }
    data.setdefault("used_stickers", []).append(p["slug"])
    return entry


def ai_post(brand, seed, data):
    mark, eyebrow, url, themes = BRANDS[brand]
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        sys.exit("ANTHROPIC_API_KEY not set")
    avoid = recent_headlines(data["entries"], brand)
    avoid_txt = ("\nDo NOT repeat these recent headlines: " + "; ".join(avoid)) if avoid else ""
    if seed:
        basis = (f"\n\nBase this post on THIS specific tip. Expand it into a punchy, accurate post and "
                 f"keep the concrete details (settings, names, numbers): {seed['idea']}")
    else:
        basis = f"\nThemes to draw from: {themes}."
    prompt = f"""You write social posts for Harbor {brand}, a privacy-first product.
A scrolling stranger gives this post about one second. The headline and the first line have to make
them stop. Voice: plain, direct, no hype, no em dashes, no emoji.{basis}

Return ONLY a JSON object with these keys:
  "head": a headline for the image card that opens a curiosity gap or names a specific surprising
          threat the reader feels instantly (max 28 chars, sentence case). Good: "Your TV is watching",
          "Delete this hidden ID". Bad: vague slogans like "Stay private" or "Protect your data".
  "sub": array of exactly 2 short supporting lines for the card that raise the stakes or hint the fix
         without giving it all away (each max 52 chars)
  "caption": the full social caption. The FIRST line must be a scroll-stopping hook (a surprising fact
             or a pointed question), then deliver the concrete tip with exact names/settings/numbers,
             ending with the line {url} and then 3-4 hashtags. 2-4 short paragraphs.

The caption must be genuinely useful and specific, a real tip people would screenshot, never generic
marketing. Lead with the problem and the surprise, not the product.

BANNED (these read as boring AI filler): openers like "Did you know", "In today's world", "We all",
"Your privacy matters", "Let's talk about", or restating the brand name. No abstractions like
"stay safe" or "take control". Every head must name a CONCRETE thing the reader can picture: a
specific device, app, setting, data type, company, or number. If the head could apply to any
privacy company, it has failed: rewrite it.{avoid_txt}"""
    body = json.dumps({
        "model": "claude-sonnet-4-6", "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(ANTHROPIC_URL, data=body, method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        data = json.load(r)
    txt = data["content"][0]["text"].strip()
    txt = txt[txt.find("{"): txt.rfind("}") + 1]
    return json.loads(txt)


def quality_ok(brand, post):
    url = BRANDS[brand][2]
    head = (post.get("head") or "").strip()
    sub  = post.get("sub") or []
    cap  = (post.get("caption") or "").strip()
    if not head or len(head) > 32:                       return "bad head"
    if not isinstance(sub, list) or len(sub) != 2:       return "bad sub"
    if any(len(s) > 56 for s in sub):                    return "sub too long"
    if not (120 <= len(cap) <= 800):                     return f"caption len {len(cap)}"
    if url not in cap:                                   return "missing link"
    if "—" in cap or "—" in head:                        return "em dash"
    low = cap.lower()
    if brand in ACCOUNT_REQUIRED and ("no account" in low or "no sign" in low or "no signup" in low):
        return "false no-account claim"
    if any(p in low for p in ["lorem", "placeholder", "as an ai", "[insert"]):
        return "placeholder text"
    return None


def render_card(stem, brand, head, sub):
    # Delegates to the shared card engine (3 layouts + spot illustrations, 4:5).
    # `sub` may be a list of lines or a string; the engine takes one subhead string.
    mark, eyebrow, url, _ = BRANDS[brand]
    if isinstance(sub, (list, tuple)):
        # join the 2 sub lines into one sentence flow with proper punctuation
        subtext = ". ".join(s.strip().rstrip(".") for s in sub if s and s.strip())
    else:
        subtext = str(sub)
    card_engine.render(stem, brand=brand, headline=head, subhead=subtext,
                       eyebrow=mark, url=url, topic=head, out_dir=str(SOCIAL_DIR))


def prune(data):
    entries = data["entries"]
    ai = [e for e in entries if e.get("source") == "ai"]
    ai.sort(key=lambda e: e.get("created", 0))
    drop = ai[:-MAX_AI] if len(ai) > MAX_AI else []
    drop_ids = {e["id"] for e in drop}
    for e in drop:
        for ext in (".png", ".svg"):
            f = SOCIAL_DIR / (e["id"] + ext)
            if f.exists():
                f.unlink()
    data["entries"] = [e for e in entries if e["id"] not in drop_ids]
    # clear stale junk images from the old AI pipeline dir
    cutoff = time.time() - JUNK_AGE_D * 86400
    freed = 0
    if IMG_JUNK.is_dir():
        for f in IMG_JUNK.iterdir():
            try:
                if f.is_file() and f.stat().st_mtime < cutoff:
                    freed += f.stat().st_size; f.unlink()
            except Exception:
                pass
    return len(drop), freed


def main():
    data = load_manifest()
    brand = pick_brand(data["entries"])
    mark, eyebrow, url, _ = BRANDS[brand]

    if brand == "stickers":
        # Serve a real designed sticker post, not an AI-generated card.
        entry = sticker_entry(data)
        # stable id per slug: drop any prior card for this slug so it refreshes
        # in place instead of accumulating (and without touching the shared image).
        data["entries"] = [e for e in data["entries"] if e.get("id") != entry["id"]]
        data["entries"].append(entry)
        dropped, freed = prune(data)
        tmp = MANIFEST.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, MANIFEST)
        print(f"added {entry['id']} | brand=stickers | pool={len(data['entries'])} | dropped {dropped} ai | freed {freed//1024}KB junk")
        return

    seed = pick_seed(data, brand)
    post = None
    for attempt in range(3):
        try:
            cand = ai_post(brand, seed, data)
        except Exception as e:
            print(f"generate attempt {attempt} failed: {e!r}"); continue
        why = quality_ok(brand, cand)
        if why is None:
            post = cand; break
        print(f"rejected (attempt {attempt}): {why}")
    if not post:
        sys.exit("no quality post produced; nothing added")

    ts = int(time.time())
    stem = f"ai-{brand}-{ts}"
    render_card(stem, brand, post["head"], post["sub"])
    link_to = seed["learn"] if (seed and seed.get("learn")) else url
    entry = {
        "id": stem, "category": "tip", "source": "ai", "brand": brand,
        "created": ts, "head": post["head"],
        "hdr": f"TIP / {post['head']} -> {url}",
        "img": f"{ASSET_BASE}/{stem}.png", "link": f"https://{link_to}",
        "tags": "lightbulb,shield", "body": post["caption"].strip(),
        "status": "pending",  # nightly AI drafts wait for approval in /social
    }
    if seed:
        data.setdefault("used_seeds", []).append(seed["id"])
        entry["seed"] = seed["id"]
    data["entries"].append(entry)
    dropped, freed = prune(data)
    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, MANIFEST)
    print(f"added {stem} | brand={brand} | pool={len(data['entries'])} | dropped {dropped} ai | freed {freed//1024}KB junk")


if __name__ == "__main__":
    main()
