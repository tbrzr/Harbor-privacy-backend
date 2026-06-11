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

SOCIAL_DIR = Path("/home/ubuntu/harbor-design-system/assets/social")
MANIFEST   = SOCIAL_DIR / "manifest.json"
TIP_BANK   = Path("/home/ubuntu/tip-bank.json")
ASSET_BASE = "https://assets.harborprivacy.com/raw/social"
IMG_JUNK   = Path("/var/www/network/social-images")
MAX_AI     = 24          # cap on AI-generated entries in the pool
JUNK_AGE_D = 14          # delete social-images files older than this many days

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
    "stickers":("HARBOR / STICKERS","STICKER DROP", "harborprivacy.com/stickers",
                "die-cut vinyl laptop stickers with privacy slogans like My DNS is mine, I read the privacy policy, and Cookies declined, "
                "weatherproof and matte, now open for preorder shipping in 2 to 3 weeks, 4 dollars each or 18 for the pack of nine, for homelab and privacy people"),
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
Voice: plain, direct, no hype, no em dashes, no emoji.{basis}

Return ONLY a JSON object with these keys:
  "head": a 2-5 word punchy headline for an image card (max 28 chars, sentence case)
  "sub": array of exactly 2 short supporting lines for the card (each max 52 chars)
  "caption": the full social caption, 2-4 short paragraphs, ending with the line {url} and then 3-4 hashtags

The caption must be genuinely useful and specific (a real tip people would screenshot), not generic marketing.{avoid_txt}"""
    body = json.dumps({
        "model": "claude-haiku-4-5-20251001", "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST",
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
    mark, eyebrow, url, _ = BRANDS[brand]
    head = head.strip(); head = head[0].upper() + head[1:]
    lines = textwrap.wrap(head, width=20)[:4] or [head]
    longest = max(len(l) for l in lines)
    fs = 92 if longest <= 14 else (76 if longest <= 18 else 62)
    lh = int(fs * 1.12); y0 = 330 if len(lines) >= 3 else 410
    headsvg = "".join(f'<text x="90" y="{y0+i*lh}" font-family="DM Serif Display, Georgia, serif" '
                      f'font-size="{fs}" fill="{INK}">{html.escape(l)}</text>' for i, l in enumerate(lines))
    sub_y = max(y0 + len(lines) * lh + 40, 600)
    subsvg = "".join(f'<text x="90" y="{sub_y+i*52}" font-family="DM Sans, system-ui, sans-serif" '
                     f'font-size="33" fill="{INK if i==0 else MUTE}" font-weight="400">{html.escape(s)}</text>'
                     for i, s in enumerate(sub))
    ew = 22 + len(eyebrow) * 12
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 1080">
  <defs><pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse"><path d="M 60 0 L 0 0 0 60" fill="none" stroke="{GRID}" stroke-width="1"/></pattern>
  <radialGradient id="glow" cx="50%" cy="-5%" r="65%"><stop offset="0%" stop-color="rgba(31,93,107,0.10)"/><stop offset="100%" stop-color="rgba(31,93,107,0)"/></radialGradient></defs>
  <rect width="1080" height="1080" fill="{BG}"/><rect width="1080" height="1080" fill="url(#grid)" opacity="0.55"/><rect width="1080" height="1080" fill="url(#glow)"/>
  <rect x="36" y="36" width="1008" height="1008" rx="24" ry="24" fill="none" stroke="{GRID}" stroke-width="2"/>
  <text x="90" y="148" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="26" fill="{TEAL}" letter-spacing="7" font-weight="500">{mark}</text>
  <g transform="translate(90, 198)"><rect x="0" y="0" width="{ew}" height="38" rx="19" ry="19" fill="none" stroke="{TEAL}" stroke-width="1.5"/>
  <text x="{ew/2}" y="25" text-anchor="middle" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="13" fill="{TEAL}" letter-spacing="3" font-weight="500">{eyebrow}</text></g>
  {headsvg}
  {subsvg}
  <line x1="90" y1="900" x2="990" y2="900" stroke="{GRID}" stroke-width="1.5"/>
  <circle cx="930" cy="150" r="44" fill="none" stroke="{TERRA}" stroke-width="6" opacity="0.9"/><line x1="930" y1="128" x2="930" y2="158" stroke="{TERRA}" stroke-width="8" stroke-linecap="round"/><circle cx="930" cy="176" r="5" fill="{TERRA}"/>
  <text x="990" y="970" text-anchor="end" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="22" fill="{TEAL}" letter-spacing="3" font-weight="500">{url}</text></svg>'''
    svgp = SOCIAL_DIR / (stem + ".svg"); pngp = SOCIAL_DIR / (stem + ".png")
    svgp.write_text(svg)
    subprocess.run(["rsvg-convert", "-w", "1080", "-h", "1080", str(svgp), "-o", str(pngp)],
                   check=True, timeout=30)


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
