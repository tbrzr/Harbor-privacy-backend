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
_spec = importlib.util.spec_from_file_location("social_refresh", "/home/ubuntu/social-refresh.py")
sr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sr)

SOCIAL_DIR = sr.SOCIAL_DIR
MANIFEST   = sr.MANIFEST
ASSET_BASE = sr.ASSET_BASE
BRANDS     = sr.BRANDS
ACCOUNT_REQUIRED = sr.ACCOUNT_REQUIRED
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
Voice: plain, direct, no hype, no em dashes, no emoji. {basis}

Return ONLY a JSON object with these keys:
  "hook": a 2-5 word scroll-stopping opener (max 24 chars, sentence case)
  "steps": array of 3 to 5 ultra-short lines that walk through the tip in order (each max 38 chars, imperative, no numbering)
  "caption": the post caption, 2-3 short paragraphs, ending with the line {url} then 3-4 hashtags

Steps must be concrete and screenshot-worthy, not vague marketing.{avoid_txt}"""
    body = json.dumps({
        "model": "claude-haiku-4-5-20251001", "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST",
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
    cap   = (p.get("caption") or "").strip()
    if not hook or len(hook) > 32:                          return "bad hook"
    if not isinstance(steps, list) or not (3 <= len(steps) <= 5): return "bad steps count"
    steps = [(s or "").strip() for s in steps]
    if any(not s or len(s) > 46 for s in steps):            return "step len"
    if not (120 <= len(cap) <= 800):                        return f"caption len {len(cap)}"
    if url not in cap:                                      return "missing link"
    blob = hook + cap + "".join(steps)
    if DASH in blob or ENDASH in blob:                      return "em dash"
    low = cap.lower()
    if brand in ACCOUNT_REQUIRED and ("no account" in low or "no sign" in low or "no signup" in low):
        return "false no-account claim"
    if any(x in low for x in ["lorem", "placeholder", "as an ai", "[insert"]):
        return "placeholder text"
    return None


def _wrap(s, w):
    return textwrap.wrap(s, width=w) or [s]


def scene_svg(brand, hook, steps, n_steps, cta=False):
    """One full-frame 1080x1920 scene. n_steps controls how many steps are shown
    (they accumulate scene by scene); cta swaps the body for the closing call."""
    mark, eyebrow, url, _ = BRANDS[brand]
    ew = 22 + len(eyebrow) * 12
    p = [f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}">
  <defs><pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse"><path d="M 60 0 L 0 0 0 60" fill="none" stroke="{GRID}" stroke-width="1"/></pattern>
  <radialGradient id="glow" cx="50%" cy="-2%" r="55%"><stop offset="0%" stop-color="rgba(31,93,107,0.12)"/><stop offset="100%" stop-color="rgba(31,93,107,0)"/></radialGradient></defs>
  <rect width="{W}" height="{H}" fill="{BG}"/><rect width="{W}" height="{H}" fill="url(#grid)" opacity="0.5"/><rect width="{W}" height="{H}" fill="url(#glow)"/>
  <rect x="36" y="36" width="{W-72}" height="{H-72}" rx="28" ry="28" fill="none" stroke="{GRID}" stroke-width="2"/>
  <text x="90" y="170" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="28" fill="{TEAL}" letter-spacing="7" font-weight="500">{html.escape(mark)}</text>
  <g transform="translate(90, 210)"><rect x="0" y="0" width="{ew}" height="40" rx="20" ry="20" fill="none" stroke="{TEAL}" stroke-width="1.5"/>
  <text x="{ew/2}" y="27" text-anchor="middle" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="14" fill="{TEAL}" letter-spacing="3" font-weight="500">{html.escape(eyebrow)}</text></g>''']

    hook = hook.strip(); hook = hook[0].upper() + hook[1:]
    hlines = _wrap(hook, 15)[:3]
    longest = max(len(l) for l in hlines)
    fs = 120 if longest <= 10 else (100 if longest <= 14 else 82)
    lh = int(fs * 1.1); y0 = 520
    for i, l in enumerate(hlines):
        p.append(f'<text x="90" y="{y0+i*lh}" font-family="DM Serif Display, Georgia, serif" '
                 f'font-size="{fs}" fill="{INK}">{html.escape(l)}</text>')

    if cta:
        p.append(f'<text x="90" y="1140" font-family="DM Sans, system-ui, sans-serif" '
                 f'font-size="48" fill="{MUTE}">Free to start. Try it:</text>')
        p.append(f'<text x="90" y="1240" font-family="DM Mono, ui-monospace, Menlo, monospace" '
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


def main():
    data = sr.load_manifest()
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    brand = arg if arg in BRANDS else sr.pick_brand(data["entries"])
    mark, eyebrow, url, _ = BRANDS[brand]
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

    scenes, durs = [], []
    s0 = SOCIAL_DIR / f"{stem}.s0.png"
    render_png(scene_svg(brand, post["hook"], steps, 0), s0); scenes.append(s0); durs.append(2.4)
    for i in range(1, len(steps) + 1):
        sp = SOCIAL_DIR / f"{stem}.s{i}.png"
        render_png(scene_svg(brand, post["hook"], steps, i), sp); scenes.append(sp); durs.append(1.9)
    sc = SOCIAL_DIR / f"{stem}.cta.png"
    render_png(scene_svg(brand, post["hook"], steps, len(steps), cta=True), sc); scenes.append(sc); durs.append(2.6)

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
        data.setdefault("used_seeds", []).append(seed["id"]); entry["seed"] = seed["id"]
    data["entries"].append(entry)
    dropped = prune_reels(data)

    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2)); os.replace(tmp, MANIFEST)
    secs = sum(durs) - 0.4 * (len(scenes) - 1)
    print(f"added {stem} | brand={brand} | steps={len(steps)} | ~{secs:.1f}s | reels pruned {dropped}")


if __name__ == "__main__":
    main()
