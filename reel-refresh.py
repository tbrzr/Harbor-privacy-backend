#!/usr/bin/env python3
"""Generate ONE silent vertical reel (1080x1920 mp4) for a Harbor brand, render a
square poster, append it to the social manifest, and prune old reels.

Silent on purpose: add Facebook / Instagram's licensed in-app music at upload time.

Reuses the proven spine of social-refresh.py (brand rotation, tip-bank seeds,
AI copy, manifest IO) so there is no logic to keep in sync twice.

Run from a root cron that sources /etc/harbor-dashboard.env (for ANTHROPIC_API_KEY):
  set -a; . /etc/harbor-dashboard.env; set +a; python3 /home/ubuntu/reel-refresh.py
"""
import os, sys, json, time, html, textwrap, subprocess, importlib.util, urllib.request
from pathlib import Path

# social-refresh.py has a hyphen (not importable by name) -> load by path.
# Its main() is guarded by __name__=="__main__", so importing runs no side effects.
_spec = importlib.util.spec_from_file_location("social_refresh", "/home/ubuntu/harbor-backend/social-refresh.py")
sr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sr)

SOCIAL_DIR = sr.SOCIAL_DIR
MANIFEST   = sr.MANIFEST
ASSET_BASE = sr.ASSET_BASE
BRANDS     = sr.BRANDS
ACCOUNT_REQUIRED = sr.ACCOUNT_REQUIRED
ANTHROPIC_URL = sr.ANTHROPIC_URL
BG, GRID, INK, MUTE, TEAL, TERRA = sr.BG, sr.GRID, sr.INK, sr.MUTE, sr.TEAL, sr.TERRA

W, H      = 1080, 1920
MAX_REELS = 12          # cap reels in the pool; oldest pruned with their files
DASH, ENDASH = "—", "–"


def reel_post(brand, seed, data):
    """Ask the model for a reel script: a hook, ordered steps, and a caption."""
    mark, eyebrow, url, themes = BRANDS[brand]
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        sys.exit("ANTHROPIC_API_KEY not set")
    avoid = sr.recent_headlines(data["entries"], brand)
    avoid_txt = ("\nDo NOT repeat these recent hooks: " + "; ".join(avoid)) if avoid else ""
    basis = (f"Base it on THIS tip and keep the concrete settings, names, and numbers: {seed['idea']}"
             if seed else f"Themes to draw from: {themes}.")
    prompt = f"""You script a SHORT vertical phone reel for Harbor {brand}, a privacy-first product.
The job of the first frame is to make a scrolling stranger STOP and need the answer, then hold them
to the end. Voice: plain, direct, no hype, no em dashes, no emoji. {basis}

Build an open loop: the hook raises a question or a stake, the steps walk toward it, and the answer is
withheld until the payoff. Do not give away the payoff in the hook.

Return ONLY a JSON object with these keys:
  "hook": a scroll-stopping opener that opens a curiosity gap or names a specific stakes/threat the
          viewer feels instantly (max 30 chars, sentence case). Good: "Your TV is watching back",
          "This setting leaks your home". Bad: vague slogans like "Stay private".
  "steps": array of 3 to 5 ultra-short lines that move the viewer through the tip in order and keep
           tension building toward the payoff (each max 38 chars, concrete, no numbering)
  "payoff": the single satisfying result line revealed at the end, the reason staying was worth it
            (max 38 chars, sentence case). Example: "Now nobody is logging it"
  "caption": the post caption, 2-3 short paragraphs, ending with the line {url} then 3-4 hashtags

Every line must be concrete and screenshot-worthy, never vague marketing.{avoid_txt}"""
    body = json.dumps({
        "model": "claude-haiku-4-5-20251001", "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(ANTHROPIC_URL, data=body, method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        d = json.load(r)
    txt = d["content"][0]["text"].strip()
    txt = txt[txt.find("{"): txt.rfind("}") + 1]
    return json.loads(txt)


def reel_ok(brand, p):
    url = BRANDS[brand][2]
    hook  = (p.get("hook") or "").strip()
    steps = p.get("steps") or []
    payoff= (p.get("payoff") or "").strip()
    cap   = (p.get("caption") or "").strip()
    if not hook or len(hook) > 34:                          return "bad hook"
    if not isinstance(steps, list) or not (3 <= len(steps) <= 5): return "bad steps count"
    steps = [(s or "").strip() for s in steps]
    if any(not s or len(s) > 46 for s in steps):            return "step len"
    if not payoff or len(payoff) > 44:                      return "bad payoff"
    if not (120 <= len(cap) <= 800):                        return f"caption len {len(cap)}"
    if url not in cap:                                      return "missing link"
    blob = hook + cap + payoff + "".join(steps)
    if DASH in blob or ENDASH in blob:                      return "em dash"
    low = cap.lower()
    if brand in ACCOUNT_REQUIRED and ("no account" in low or "no sign" in low or "no signup" in low):
        return "false no-account claim"
    if any(x in low for x in ["lorem", "placeholder", "as an ai", "[insert"]):
        return "placeholder text"
    return None


def _wrap(s, w):
    return textwrap.wrap(s, width=w) or [s]


def _progress_pips(total, filled, cx0, cy, accent, dim):
    """A row of pips that fills scene by scene, a visible 'wait for it' open loop:
    empty on the hook frame, full on the payoff frame. Gives a reason to stay."""
    gap = 46
    out = []
    for i in range(total):
        on = i < filled
        out.append(f'<rect x="{cx0 + i*gap}" y="{cy}" width="30" height="8" rx="4" '
                   f'fill="{accent if on else dim}" opacity="{1 if on else 0.5}"/>')
    return "".join(out)


def scene_svg(brand, hook, steps, n_steps, cta=False, payoff=""):
    """One full-frame 1080x1920 scene. n_steps controls how many steps are shown
    (they accumulate scene by scene); cta reveals the withheld payoff + closing call."""
    mark, eyebrow, url, _ = BRANDS[brand]
    ew = 22 + len(eyebrow) * 12
    total_pips = len(steps) + 1  # one per step, plus the payoff reveal
    p = [f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}">
  <defs><pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse"><path d="M 60 0 L 0 0 0 60" fill="none" stroke="{GRID}" stroke-width="1"/></pattern>
  <radialGradient id="glow" cx="50%" cy="-2%" r="55%"><stop offset="0%" stop-color="rgba(31,93,107,0.12)"/><stop offset="100%" stop-color="rgba(31,93,107,0)"/></radialGradient></defs>
  <rect width="{W}" height="{H}" fill="{BG}"/><rect width="{W}" height="{H}" fill="url(#grid)" opacity="0.5"/><rect width="{W}" height="{H}" fill="url(#glow)"/>
  <rect x="36" y="36" width="{W-72}" height="{H-72}" rx="28" ry="28" fill="none" stroke="{GRID}" stroke-width="2"/>
  <text x="90" y="170" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="28" fill="{TEAL}" letter-spacing="7" font-weight="500">{html.escape(mark)}</text>
  <g transform="translate(90, 210)"><rect x="0" y="0" width="{ew}" height="40" rx="20" ry="20" fill="none" stroke="{TEAL}" stroke-width="1.5"/>
  <text x="{ew/2}" y="27" text-anchor="middle" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="14" fill="{TEAL}" letter-spacing="3" font-weight="500">{html.escape(eyebrow)}</text></g>''']

    filled = total_pips if cta else n_steps
    p.append(_progress_pips(total_pips, filled, 90, 300, TERRA, GRID))

    hook = hook.strip(); hook = hook[0].upper() + hook[1:]
    hlines = _wrap(hook, 15)[:3]
    longest = max(len(l) for l in hlines)
    fs = 120 if longest <= 10 else (100 if longest <= 14 else 82)
    lh = int(fs * 1.1); y0 = 520
    for i, l in enumerate(hlines):
        p.append(f'<text x="90" y="{y0+i*lh}" font-family="DM Serif Display, Georgia, serif" '
                 f'font-size="{fs}" fill="{INK}">{html.escape(l)}</text>')

    if cta:
        # The payoff reveal: the withheld answer the open loop was building to.
        if payoff:
            payoff = payoff.strip(); payoff = payoff[0].upper() + payoff[1:]
            for i, l in enumerate(_wrap(payoff, 18)[:3]):
                p.append(f'<text x="90" y="{1010+i*86}" font-family="DM Serif Display, Georgia, serif" '
                         f'font-size="76" fill="{TEAL}">{html.escape(l)}</text>')
        lead = "Preorder now:" if brand == "stickers" else "Free to start. Try it:"
        p.append(f'<text x="90" y="1430" font-family="DM Sans, system-ui, sans-serif" '
                 f'font-size="48" fill="{MUTE}">{html.escape(lead)}</text>')
        p.append(f'<text x="90" y="1530" font-family="DM Mono, ui-monospace, Menlo, monospace" '
                 f'font-size="46" fill="{TEAL}" letter-spacing="1">{html.escape(url)}</text>')
    else:
        sy = y0 + len(hlines) * lh + 120
        for idx in range(n_steps):
            wl = _wrap(steps[idx], 26)
            p.append(f'<text x="92" y="{sy}" font-family="DM Sans, system-ui, sans-serif" '
                     f'font-size="46" fill="{TERRA}" font-weight="700">&#8250;</text>')
            for j, seg in enumerate(wl):
                p.append(f'<text x="142" y="{sy+j*54}" font-family="DM Sans, system-ui, sans-serif" '
                         f'font-size="42" fill="{INK}">{html.escape(seg)}</text>')
            sy += 54 * len(wl) + 48

    p.append(f'<line x1="90" y1="{H-210}" x2="{W-90}" y2="{H-210}" stroke="{GRID}" stroke-width="1.5"/>')
    p.append(f'<circle cx="{W-150}" cy="160" r="40" fill="none" stroke="{TERRA}" stroke-width="6" opacity="0.9"/>'
             f'<line x1="{W-150}" y1="138" x2="{W-150}" y2="166" stroke="{TERRA}" stroke-width="8" stroke-linecap="round"/>'
             f'<circle cx="{W-150}" cy="184" r="5" fill="{TERRA}"/>')
    p.append(f'<text x="{W-90}" y="{H-140}" text-anchor="end" font-family="DM Mono, ui-monospace, Menlo, monospace" '
             f'font-size="30" fill="{TEAL}" letter-spacing="2" font-weight="500">{html.escape(url)}</text>')
    p.append('</svg>')
    return "".join(p)


def render_png(svg, path):
    sp = path.with_suffix(".scene.svg")
    sp.write_text(svg)
    subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), str(sp), "-o", str(path)],
                   check=True, timeout=30)
    sp.unlink()


def build_reel(scene_paths, durs, out, T=0.4):
    """Crossfade the scene frames into one mp4 using ffmpeg xfade."""
    inputs = []
    for sp, d in zip(scene_paths, durs):
        inputs += ["-loop", "1", "-t", f"{d}", "-i", str(sp)]
    fc = [f"[{i}:v]scale={W}:{H},setsar=1,fps=30,format=yuv420p[v{i}]"
          for i in range(len(scene_paths))]
    last = "v0"; cum = durs[0]
    for i in range(1, len(scene_paths)):
        nxt = f"x{i}"
        fc.append(f"[{last}][v{i}]xfade=transition=fade:duration={T}:offset={cum-T:.3f}[{nxt}]")
        last = nxt; cum += durs[i] - T
    cmd = ["ffmpeg", "-y", *inputs, "-filter_complex", ";".join(fc), "-map", f"[{last}]",
           "-c:v", "libx264", "-pix_fmt", "yuv420p", "-r", "30", "-movflags", "+faststart", str(out)]
    subprocess.run(cmd, check=True, timeout=180,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def prune_reels(data):
    entries = data["entries"]
    reels = sorted((e for e in entries if e.get("source") == "reel"),
                   key=lambda e: e.get("created", 0))
    drop = reels[:-MAX_REELS] if len(reels) > MAX_REELS else []
    ids = {e["id"] for e in drop}
    for e in drop:
        for ext in (".png", ".svg", ".mp4"):
            f = SOCIAL_DIR / (e["id"] + ext)
            if f.exists():
                f.unlink()
    data["entries"] = [e for e in entries if e["id"] not in ids]
    return len(drop)


# ---------------------------------------------------------------------------
# PET PACK: a visually distinct reel for the dog-walker / groomer sprint.
# Deep-teal frame (not the cream tip-card), pain-point-first script, amber paw
# accent, and each script points at its matching niche booking landing page.
# Invoke with `reel-refresh.py pets`.
# ---------------------------------------------------------------------------
PBG="#143f49"; PCREAM="#fbf7f1"; PSOFT="#a7c6cc"; PACC="#e8a86a"; PLINE="rgba(255,255,255,0.12)"

PET_SEEDS = [
    {"id":"pet-walker-noshow","who":"dog walker","eyebrow":"FOR DOG WALKERS","niche":"walkers",
     "learn":"harborprivacy.com/booking-for-dog-walkers",
     "idea":"clients text to cancel last minute or just no-show, blowing up the day's route"},
    {"id":"pet-groomer-double","who":"dog groomer","eyebrow":"FOR GROOMERS","niche":"groomers",
     "learn":"harborprivacy.com/booking-for-dog-groomers",
     "idea":"two dogs land in the same slot because requests come in by text, DM, and call at once"},
    {"id":"pet-sitter-holiday","who":"pet sitter","eyebrow":"FOR PET SITTERS","niche":"sitters",
     "learn":"harborprivacy.com/booking-for-pet-sitters",
     "idea":"holiday weeks fill up fast and you lose track of who asked for which dates first"},
    {"id":"pet-mobile-route","who":"mobile pet groomer","eyebrow":"MOBILE GROOMERS","niche":"mobile",
     "learn":"harborprivacy.com/booking-for-mobile-pet-groomers",
     "idea":"you are driving between houses all day and cannot pick up booking calls"},
    {"id":"pet-afterhours","who":"dog walker","eyebrow":"FOR DOG WALKERS","niche":"walkers",
     "learn":"harborprivacy.com/booking-for-dog-walkers",
     "idea":"booking requests arrive at 11pm while you sleep and the client cools off by morning"},
]
PET_NICHES = ("walkers", "groomers", "sitters", "mobile")


def pick_pet_seed(data, niche=""):
    """Least-recently-used pet seed (never-used first); optional niche filter.
    When a niche has more than one seed (walkers), still picks the stalest one."""
    pool = [s for s in PET_SEEDS if s.get("niche") == niche] if niche else PET_SEEDS
    pool = pool or PET_SEEDS
    used = data.get("used_pet_seeds", [])
    last = {sid: i for i, sid in enumerate(used)}
    return min(pool, key=lambda s: last.get(s["id"], -1))


def pet_reel_post(seed, data):
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        sys.exit("ANTHROPIC_API_KEY not set")
    avoid = sr.recent_headlines(data["entries"], "booking")
    avoid_txt = ("\nDo NOT repeat these recent hooks: " + "; ".join(avoid)) if avoid else ""
    prompt = f"""You script a SHORT vertical phone reel aimed at one solo {seed['who']} who runs the whole business off their phone.
Voice: warm, plain, talking to a single tired small-business owner. No hype, no em dashes, no emoji.
Open on this real pain: {seed['idea']}.
Harbor Booking is the fix: a free booking page where clients self-book, reschedule, and can leave a deposit, so the owner stops playing phone tag.

Return ONLY a JSON object with these keys:
  "hook": a short pain-point opener the {seed['who']} feels instantly (max 38 chars, sentence case)
  "steps": array of 3 to 4 short lines that move from the pain to the fix (each max 48 chars, no numbering)
  "caption": 2-3 short paragraphs, ending with the line {seed['learn']} then 3-4 hashtags
Make it feel like a real day on the job, concrete, not marketing.{avoid_txt}"""
    body = json.dumps({
        "model": "claude-haiku-4-5-20251001", "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(ANTHROPIC_URL, data=body, method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        d = json.load(r)
    txt = d["content"][0]["text"].strip()
    txt = txt[txt.find("{"): txt.rfind("}") + 1]
    return json.loads(txt)


def pet_ok(seed, p):
    hook  = (p.get("hook") or "").strip()
    steps = p.get("steps") or []
    cap   = (p.get("caption") or "").strip()
    if not hook or len(hook) > 44:                          return "bad hook"
    if not isinstance(steps, list) or not (3 <= len(steps) <= 4): return "bad steps count"
    steps = [(s or "").strip() for s in steps]
    if any(not s or len(s) > 54 for s in steps):            return "step len"
    if not (120 <= len(cap) <= 800):                        return f"caption len {len(cap)}"
    if seed["learn"] not in cap:                            return "missing link"
    blob = hook + cap + "".join(steps)
    if DASH in blob or ENDASH in blob:                      return "em dash"
    low = cap.lower()
    if "no account" in low or "no sign" in low:             return "false no-account claim"
    if any(x in low for x in ["lorem", "placeholder", "as an ai", "[insert"]):
        return "placeholder text"
    return None


def _paw(cx, cy, s, fill):
    """Small paw: one pad + four toes, scaled by s."""
    out = [f'<ellipse cx="{cx}" cy="{cy}" rx="{1.5*s:.1f}" ry="{1.25*s:.1f}" fill="{fill}"/>']
    for dx, dy, r in [(-1.6,-1.0,0.5),(-0.5,-1.7,0.55),(0.6,-1.7,0.55),(1.6,-1.0,0.5)]:
        out.append(f'<circle cx="{cx+dx*s:.1f}" cy="{cy+dy*s:.1f}" r="{r*s:.1f}" fill="{fill}"/>')
    return "".join(out)


def pet_scene_svg(eyebrow, url, hook, steps, n_steps, cta=False):
    """Deep-teal full-frame scene; same geometry as the cream scene, inverted palette."""
    ew = 22 + len(eyebrow) * 12
    p = [f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}">
  <defs><radialGradient id="pg" cx="50%" cy="0%" r="70%"><stop offset="0%" stop-color="rgba(232,168,106,0.16)"/><stop offset="100%" stop-color="rgba(232,168,106,0)"/></radialGradient></defs>
  <rect width="{W}" height="{H}" fill="{PBG}"/><rect width="{W}" height="{H}" fill="url(#pg)"/>
  <rect x="36" y="36" width="{W-72}" height="{H-72}" rx="28" ry="28" fill="none" stroke="{PLINE}" stroke-width="2"/>
  <text x="90" y="170" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="28" fill="{PSOFT}" letter-spacing="7" font-weight="500">HARBOR / BOOKING</text>
  <g transform="translate(90, 210)"><rect x="0" y="0" width="{ew}" height="40" rx="20" ry="20" fill="none" stroke="{PACC}" stroke-width="1.5"/>
  <text x="{ew/2}" y="27" text-anchor="middle" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="14" fill="{PACC}" letter-spacing="3" font-weight="500">{html.escape(eyebrow)}</text></g>''']
    p.append(_paw(W-150, 175, 16, PACC))
    total_pips = len(steps) + 1
    p.append(_progress_pips(total_pips, total_pips if cta else n_steps, 90, 300, PACC, PLINE))

    hook = hook.strip(); hook = hook[0].upper() + hook[1:]
    hlines = _wrap(hook, 15)[:3]
    longest = max(len(l) for l in hlines)
    fs = 120 if longest <= 10 else (100 if longest <= 14 else 82)
    lh = int(fs * 1.1); y0 = 520
    for i, l in enumerate(hlines):
        p.append(f'<text x="90" y="{y0+i*lh}" font-family="DM Serif Display, Georgia, serif" '
                 f'font-size="{fs}" fill="{PCREAM}">{html.escape(l)}</text>')

    if cta:
        p.append(f'<text x="90" y="1140" font-family="DM Sans, system-ui, sans-serif" '
                 f'font-size="48" fill="{PSOFT}">Free booking page. Start here:</text>')
        p.append(f'<text x="90" y="1240" font-family="DM Mono, ui-monospace, Menlo, monospace" '
                 f'font-size="46" fill="{PACC}" letter-spacing="1">{html.escape(url)}</text>')
    else:
        sy = y0 + len(hlines) * lh + 120
        for idx in range(n_steps):
            wl = _wrap(steps[idx], 26)
            p.append(f'<text x="92" y="{sy}" font-family="DM Sans, system-ui, sans-serif" '
                     f'font-size="46" fill="{PACC}" font-weight="700">&#8250;</text>')
            for j, seg in enumerate(wl):
                p.append(f'<text x="142" y="{sy+j*54}" font-family="DM Sans, system-ui, sans-serif" '
                         f'font-size="42" fill="{PCREAM}">{html.escape(seg)}</text>')
            sy += 54 * len(wl) + 48

    p.append(f'<line x1="90" y1="{H-210}" x2="{W-90}" y2="{H-210}" stroke="{PLINE}" stroke-width="1.5"/>')
    p.append(f'<text x="{W-90}" y="{H-140}" text-anchor="end" font-family="DM Mono, ui-monospace, Menlo, monospace" '
             f'font-size="30" fill="{PSOFT}" letter-spacing="2" font-weight="500">{html.escape(url)}</text>')
    p.append('</svg>')
    return "".join(p)


def pet_poster_svg(eyebrow, hook, steps):
    """Square 1080 dark poster for the dashboard grid (matches the reel look)."""
    S = 1080; ew = 22 + len(eyebrow) * 12
    hook = hook.strip(); hook = hook[0].upper() + hook[1:]
    hl = _wrap(hook, 14)[:3]; longest = max(len(l) for l in hl)
    fs = 104 if longest <= 10 else (86 if longest <= 14 else 72); lh = int(fs * 1.1); y0 = 430
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {S} {S}">',
         f'<defs><radialGradient id="pg2" cx="50%" cy="0%" r="80%"><stop offset="0%" stop-color="rgba(232,168,106,0.16)"/><stop offset="100%" stop-color="rgba(232,168,106,0)"/></radialGradient></defs>',
         f'<rect width="{S}" height="{S}" fill="{PBG}"/><rect width="{S}" height="{S}" fill="url(#pg2)"/>',
         f'<rect x="28" y="28" width="{S-56}" height="{S-56}" rx="26" ry="26" fill="none" stroke="{PLINE}" stroke-width="2"/>',
         f'<text x="72" y="130" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="24" fill="{PSOFT}" letter-spacing="6" font-weight="500">HARBOR / BOOKING</text>',
         f'<g transform="translate(72,162)"><rect width="{ew}" height="38" rx="19" ry="19" fill="none" stroke="{PACC}" stroke-width="1.5"/><text x="{ew/2}" y="25" text-anchor="middle" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="13" fill="{PACC}" letter-spacing="3">{html.escape(eyebrow)}</text></g>']
    p.append(_paw(S-130, 150, 14, PACC))
    for i, l in enumerate(hl):
        p.append(f'<text x="72" y="{y0+i*lh}" font-family="DM Serif Display, Georgia, serif" '
                 f'font-size="{fs}" fill="{PCREAM}">{html.escape(l)}</text>')
    sy = y0 + len(hl) * lh + 70
    for s in steps[:2]:
        wl = _wrap(s, 30)
        p.append(f'<text x="74" y="{sy}" font-family="DM Sans, system-ui, sans-serif" '
                 f'font-size="40" fill="{PACC}" font-weight="700">&#8250;</text>')
        for j, seg in enumerate(wl):
            p.append(f'<text x="120" y="{sy+j*48}" font-family="DM Sans, system-ui, sans-serif" '
                     f'font-size="36" fill="{PCREAM}">{html.escape(seg)}</text>')
        sy += 48 * len(wl) + 34
    p.append(f'<text x="72" y="{S-70}" font-family="DM Mono, ui-monospace, Menlo, monospace" '
             f'font-size="26" fill="{PSOFT}" letter-spacing="2">harborprivacy.com/booking</text>')
    p.append('</svg>')
    return "".join(p)


def render_square(svg, path, S=1080):
    sp = path.with_suffix(".pp.svg"); sp.write_text(svg)
    subprocess.run(["rsvg-convert", "-w", str(S), "-h", str(S), str(sp), "-o", str(path)],
                   check=True, timeout=30)
    sp.unlink()


def main_pets(data, niche=""):
    seed = pick_pet_seed(data, niche)
    post = None
    for a in range(5):
        try:
            cand = pet_reel_post(seed, data)
        except Exception as e:
            print(f"generate attempt {a} failed: {e!r}"); continue
        why = pet_ok(seed, cand)
        if why is None:
            post = cand; break
        print(f"rejected (attempt {a}): {why}")
    if not post:
        sys.exit("no quality pet reel produced; nothing added")

    ts = int(time.time()); stem = f"reel-petbooking-{ts}"
    steps = [s.strip() for s in post["steps"]]
    url = "harborprivacy.com/booking"; eyebrow = seed["eyebrow"]

    scenes, durs = [], []
    s0 = SOCIAL_DIR / f"{stem}.s0.png"
    render_png(pet_scene_svg(eyebrow, url, post["hook"], steps, 0), s0); scenes.append(s0); durs.append(2.8)
    for i in range(1, len(steps) + 1):
        sp = SOCIAL_DIR / f"{stem}.s{i}.png"
        render_png(pet_scene_svg(eyebrow, url, post["hook"], steps, i), sp); scenes.append(sp); durs.append(2.0)
    sc = SOCIAL_DIR / f"{stem}.cta.png"
    render_png(pet_scene_svg(eyebrow, url, post["hook"], steps, len(steps), cta=True), sc); scenes.append(sc); durs.append(3.0)

    build_reel(scenes, durs, SOCIAL_DIR / f"{stem}.mp4")
    render_square(pet_poster_svg(eyebrow, post["hook"], steps), SOCIAL_DIR / f"{stem}.png")
    for p in scenes:
        try: p.unlink()
        except Exception: pass

    entry = {
        "id": stem, "category": "tip", "source": "reel", "brand": "booking", "created": ts,
        "head": post["hook"], "hdr": f"REEL / {post['hook']} -> {seed['learn']}",
        "img": f"{ASSET_BASE}/{stem}.png", "video": f"{ASSET_BASE}/{stem}.mp4",
        "link": f"https://{seed['learn']}", "tags": "calendar,shield", "body": post["caption"].strip(),
        "seed": seed["id"],
    }
    data["entries"].append(entry)
    data.setdefault("used_pet_seeds", []).append(seed["id"])
    dropped = prune_reels(data)

    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2)); os.replace(tmp, MANIFEST)
    secs = sum(durs) - 0.4 * (len(scenes) - 1)
    print(f"added {stem} | PET {seed['eyebrow']} | steps={len(steps)} | ~{secs:.1f}s | -> {seed['learn']} | reels pruned {dropped}")


def main():
    data = sr.load_manifest()
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg in ("pets", "--pets"):
        niche = sys.argv[2].strip().lower() if len(sys.argv) > 2 else ""
        return main_pets(data, niche if niche in PET_NICHES else "")
    brand = arg if arg in BRANDS else sr.pick_brand(data["entries"])
    mark, eyebrow, url, _ = BRANDS[brand]
    # Optional ad-hoc reel: `reel-refresh.py <brand> "<idea>" [link-slug]`.
    # The idea is a one-off seed (skips the tip-bank rotation) and the optional
    # link-slug (e.g. harborprivacy.com/booking-for-dog-walkers) becomes the
    # post link so niche landing pages can be promoted. The on-screen CTA url
    # stays the brand default to avoid overflowing the scene.
    idea = sys.argv[2].strip() if len(sys.argv) > 2 else ""
    learn = sys.argv[3].strip() if len(sys.argv) > 3 else ""
    if idea:
        seed = {"id": "adhoc", "idea": idea, "learn": learn or None}
    else:
        seed = sr.pick_seed(data, brand)

    post = None
    for a in range(5):
        try:
            cand = reel_post(brand, seed, data)
        except Exception as e:
            print(f"generate attempt {a} failed: {e!r}"); continue
        why = reel_ok(brand, cand)
        if why is None:
            post = cand; break
        print(f"rejected (attempt {a}): {why}")
    if not post:
        sys.exit("no quality reel produced; nothing added")

    ts = int(time.time()); stem = f"reel-{brand}-{ts}"
    steps = [s.strip() for s in post["steps"]]

    payoff = post.get("payoff", "")
    scenes, durs = [], []
    s0 = SOCIAL_DIR / f"{stem}.s0.png"
    # Hold the hook a beat longer so the curiosity gap lands before the first step.
    render_png(scene_svg(brand, post["hook"], steps, 0), s0); scenes.append(s0); durs.append(2.8)
    for i in range(1, len(steps) + 1):
        sp = SOCIAL_DIR / f"{stem}.s{i}.png"
        render_png(scene_svg(brand, post["hook"], steps, i), sp); scenes.append(sp); durs.append(2.0)
    sc = SOCIAL_DIR / f"{stem}.cta.png"
    render_png(scene_svg(brand, post["hook"], steps, len(steps), cta=True, payoff=payoff), sc)
    scenes.append(sc); durs.append(3.2)

    build_reel(scenes, durs, SOCIAL_DIR / f"{stem}.mp4")
    # Square poster for the dashboard grid (reuse the card renderer).
    sr.render_card(stem, brand, post["hook"], steps[:2])
    for p in scenes:
        try: p.unlink()
        except Exception: pass

    link_to = seed["learn"] if (seed and seed.get("learn")) else url
    entry = {
        "id": stem, "category": "tip", "source": "reel", "brand": brand, "created": ts,
        "head": post["hook"], "hdr": f"REEL / {post['hook']} -> {url}",
        "img": f"{ASSET_BASE}/{stem}.png", "video": f"{ASSET_BASE}/{stem}.mp4",
        "link": f"https://{link_to}", "tags": "lightbulb,shield", "body": post["caption"].strip(),
    }
    if seed:
        entry["seed"] = seed["id"]
        if seed["id"] != "adhoc":  # don't pollute the tip-bank rotation
            data.setdefault("used_seeds", []).append(seed["id"])
    data["entries"].append(entry)
    dropped = prune_reels(data)

    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2)); os.replace(tmp, MANIFEST)
    secs = sum(durs) - 0.4 * (len(scenes) - 1)
    print(f"added {stem} | brand={brand} | steps={len(steps)} | ~{secs:.1f}s | reels pruned {dropped}")


if __name__ == "__main__":
    main()
