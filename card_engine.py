#!/usr/bin/env python3
"""Harbor social card engine — native.no-style 4:5 cards in pure SVG.

Shared by the nightly cron (social-refresh.py) and the dashboard Generate button
so both produce identical output. Three layouts (big-type / hero-illustration /
bold-object), 8 spot illustrations, chosen per post: an illustration is matched by
topic keyword, the layout is picked from a hash of the post id (deterministic
variety), and posts that match no illustration fall back to a clean big-type card.

Public API:
    render(stem, *, brand, headline, subhead, eyebrow, url, topic, out_dir) -> Path
writes <out_dir>/<stem>.svg and <out_dir>/<stem>.png (1080x1350) and returns the png path.

Render is via rsvg-convert (librsvg). NOTE: librsvg 2.52 mishandles feDropShadow,
so depth shadows are built from feGaussianBlur+feOffset+feMerge — do not "simplify"
that filter back to feDropShadow.
"""
import html, subprocess, textwrap, hashlib
from pathlib import Path

BG="#fbf7f1"; INK="#1a2420"; MUTE="#6b7a72"; TEAL="#1f5d6b"
SAGE="#cdd8c8"; GREEN="#3d6b52"; LINE="#e5dfd3"; TAN="#e9e2d4"; DARK="#17424b"
W, H = 1080, 1350


# ── decorative motifs ────────────────────────────────────────────────────────
def dotgrid(x,y,cols,rows,gap=20,r=3,color=SAGE,op=0.5):
    return "".join(f'<circle cx="{x+c*gap}" cy="{y+rr*gap}" r="{r}" fill="{color}" opacity="{op}"/>'
                   for c in range(cols) for rr in range(rows))

def blob(cx,cy,scale,color=SAGE,op=1.0):
    return (f'<path transform="translate({cx},{cy}) scale({scale})" opacity="{op}" fill="{color}" '
            f'd="M40 -60 C 70 -45, 90 -10, 80 25 C 70 60, 30 85, -10 80 C -50 75, -85 50, -88 12 '
            f'C -90 -25, -65 -60, -30 -72 C 0 -82, 20 -75, 40 -60 Z"/>')

def plusmark(x,y,s=16,color=GREEN):
    return f'<path d="M{x-s} {y} H{x+s} M{x} {y-s} V{y+s}" stroke="{color}" stroke-width="4" stroke-linecap="round"/>'

def papergrid():
    return (f'<g opacity="0.5"><rect x="900" y="-40" width="240" height="240" rx="40" fill="none" stroke="{LINE}" stroke-width="3"/>'
            f'<path d="M900 40 H1140 M900 120 H1140 M980 -40 V200 M1060 -40 V200" stroke="{LINE}" stroke-width="2"/></g>')


# ── spot illustrations (flat soft-3D: gradient face + darker offset copy) ─────
def illo_padlock(cx,cy,scale=1.0,color="url(#tealgrad)"):
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <rect x="-118" y="-2" width="236" height="200" rx="42" fill="{DARK}"/>
      <rect x="-130" y="-14" width="236" height="200" rx="42" fill="{color}"/>
      <path d="M-78 -14 V-60 a66 66 0 0 1 132 0 V-14" fill="none" stroke="{color}" stroke-width="34" stroke-linecap="round"/>
      <rect x="-26" y="58" width="52" height="60" rx="14" fill="{BG}"/><circle cx="0" cy="74" r="16" fill="{BG}"/></g>'''

def illo_shield(cx,cy,scale=1.0,color="url(#tealgrad)"):
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <path transform="translate(12,12)" fill="{DARK}" d="M0 -140 C 48 -108, 104 -100, 116 -96 C 116 0, 80 84, 0 132 C -80 84, -116 0, -116 -96 C -104 -100, -48 -108, 0 -140 Z"/>
      <path fill="{color}" d="M0 -140 C 48 -108, 104 -100, 116 -96 C 116 0, 80 84, 0 132 C -80 84, -116 0, -116 -96 C -104 -100, -48 -108, 0 -140 Z"/>
      <path d="M-44 -8 L-10 30 L52 -44" fill="none" stroke="{BG}" stroke-width="22" stroke-linecap="round" stroke-linejoin="round"/></g>'''

def illo_pricetag(cx,cy,scale=1.0):
    tagpath = "M-120 -150 H120 a16 16 0 0 1 16 16 V58 L0 180 L-136 58 V-134 a16 16 0 0 1 16 -16 Z"
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <path transform="translate(10,12)" d="{tagpath}" fill="{DARK}" opacity="0.55"/>
      <path d="{tagpath}" fill="{TAN}" stroke="{INK}" stroke-width="6" stroke-linejoin="round"/>
      <circle cx="0" cy="-104" r="20" fill="{BG}" stroke="{INK}" stroke-width="6"/>
      <text x="0" y="-8" font-family="DM Serif Display, Georgia, serif" font-size="74" fill="{GREEN}" text-anchor="middle">$0.00</text>
      <line x1="-96" y1="-28" x2="96" y2="-28" stroke="{TEAL}" stroke-width="7"/>
      <g transform="translate(0,96)">
        <rect x="-42" y="-2" width="84" height="70" rx="14" fill="{GREEN}"/>
        <path d="M-26 -2 V-26 a26 26 0 0 1 52 0 V-2" fill="none" stroke="{GREEN}" stroke-width="16"/>
        <rect x="-9" y="22" width="18" height="24" rx="5" fill="{TAN}"/></g></g>'''

def illo_eye(cx,cy,scale=1.0,color="url(#tealgrad)"):
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <path transform="translate(10,12)" fill="{DARK}" d="M-150 0 C -80 -86, 80 -86, 150 0 C 80 86, -80 86, -150 0 Z"/>
      <path fill="{color}" d="M-150 0 C -80 -86, 80 -86, 150 0 C 80 86, -80 86, -150 0 Z"/>
      <circle cx="0" cy="0" r="52" fill="{BG}"/><circle cx="0" cy="0" r="24" fill="{INK}"/>
      <line x1="-130" y1="-108" x2="130" y2="108" stroke="{GREEN}" stroke-width="28" stroke-linecap="round"/></g>'''

def illo_wifi(cx,cy,scale=1.0,color="url(#tealgrad)"):
    arcs = "".join(f'<path d="M{-r*0.78} {-r*0.16} A {r} {r} 0 0 1 {r*0.78} {-r*0.16}" fill="none" stroke="{color}" stroke-width="30" stroke-linecap="round" transform="translate(0,40)"/>'
                   for r in (60,118,176))
    return f'''<g transform="translate({cx},{cy}) scale({scale})">{arcs}
      <circle cx="0" cy="70" r="24" fill="{color}"/>
      <line x1="-156" y1="-156" x2="156" y2="156" stroke="{GREEN}" stroke-width="28" stroke-linecap="round"/></g>'''

def illo_mail(cx,cy,scale=1.0,color="url(#tealgrad)"):
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <rect transform="translate(10,12)" x="-150" y="-100" width="300" height="200" rx="22" fill="{DARK}"/>
      <rect x="-150" y="-100" width="300" height="200" rx="22" fill="{color}"/>
      <path d="M-150 -86 L0 36 L150 -86" fill="none" stroke="{BG}" stroke-width="20" stroke-linecap="round" stroke-linejoin="round"/></g>'''

def illo_barcode(cx,cy,scale=1.0,color=INK):
    widths=[7,4,12,5,7,16,4,9,5,7,12,4,7,5,14,7,4,9,5,12,7,4,9,5,7]
    x=-150; bars=[]
    for i,w in enumerate(widths):
        c = TEAL if i in (5,14,19) else color
        bars.append(f'<rect x="{x}" y="-86" width="{w}" height="150" fill="{c}"/>')
        x += w + 8
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <rect transform="translate(10,12)" x="-184" y="-128" width="368" height="248" rx="20" fill="{DARK}" opacity="0.5"/>
      <rect x="-184" y="-128" width="368" height="248" rx="20" fill="{BG}" stroke="{LINE}" stroke-width="4"/>
      {''.join(bars)}
      <text x="0" y="104" font-family="DM Mono, monospace" font-size="30" fill="{INK}" letter-spacing="3" text-anchor="middle">0  71943  22087  0</text></g>'''

def illo_card(cx,cy,scale=1.0,color="url(#tealgrad)"):
    # credit/debit card: magnetic stripe + tan chip + number blocks
    nums="".join(f'<rect x="{-130+i*78}" y="58" width="58" height="14" rx="7" fill="{BG}" opacity="0.85"/>' for i in range(4))
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <rect transform="translate(10,14)" x="-165" y="-105" width="330" height="210" rx="24" fill="{DARK}" opacity="0.5"/>
      <rect x="-165" y="-105" width="330" height="210" rx="24" fill="{color}"/>
      <rect x="-165" y="-66" width="330" height="40" fill="{DARK}"/>
      <rect x="-128" y="4" width="62" height="48" rx="9" fill="{TAN}"/>
      <path d="M-128 28 H-66 M-107 4 V52 M-87 4 V52" stroke="{DARK}" stroke-width="3" opacity="0.4"/>
      {nums}</g>'''

def illo_doc(cx,cy,scale=1.0,color="url(#tealgrad)"):
    # document/fax page with a folded corner + text lines
    page="M-112 -150 H62 L112 -100 V150 H-112 Z"
    fold="M62 -150 L112 -100 H62 Z"
    ys=[-66,-26,14,54,94]
    lines="".join(f'<line x1="-74" y1="{y}" x2="{74 if i<4 else 18}" y2="{y}" stroke="{BG}" stroke-width="13" stroke-linecap="round" opacity="0.9"/>'
                  for i,y in enumerate(ys))
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <path transform="translate(10,12)" d="{page}" fill="{DARK}" opacity="0.5"/>
      <path d="{page}" fill="{color}"/>
      <path d="{fold}" fill="{DARK}" opacity="0.35"/>
      {lines}</g>'''

def illo_router(cx,cy,scale=1.0,color="url(#tealgrad)"):
    return f'''<g transform="translate({cx},{cy}) scale({scale})">
      <rect transform="translate(8,12)" x="-160" y="20" width="320" height="110" rx="22" fill="{DARK}"/>
      <rect x="-160" y="20" width="320" height="110" rx="22" fill="{color}"/>
      <circle cx="-110" cy="75" r="14" fill="{BG}"/><circle cx="-60" cy="75" r="14" fill="{BG}"/>
      <rect x="60" y="64" width="80" height="22" rx="11" fill="{BG}"/>
      <line x1="-90" y1="20" x2="-130" y2="-70" stroke="{color}" stroke-width="16" stroke-linecap="round"/>
      <line x1="90" y1="20" x2="130" y2="-70" stroke="{color}" stroke-width="16" stroke-linecap="round"/>
      <circle cx="-130" cy="-82" r="14" fill="{GREEN}"/><circle cx="130" cy="-82" r="14" fill="{GREEN}"/></g>'''


# ── topic -> illustration map (first keyword hit wins; (fn, tilt)) ────────────
# keyword -> illustration asset key (PNG in ILLO_DIR). First match wins.
ILLO_MAP = [
    (("broker","people search","people-search","for sale","spokeo","whitepages","beenverified",
      "relatives","opt-out","opt out","listed","reverse phone"), "pricetag"),
    (("masked email","burner","alias","forward","spam","signup","sign up","inbox","newsletter",
      "old account","old accounts","dormant","forgotten account","breach","leaked","data breach","gmail"), "mail"),
    (("free app","costs the most","cost the most","paying with","price","$0","hidden cost","really paying"), "pricetag"),
    (("fax","faxing","document","documents","docs","paperwork","hipaa","medical record","notar","signature"), "doc"),
    (("credit","debit","budget","bank","banking","spending","receipt","statement","prescreen",
      "paycheck","subscription","money","overdraft","mint","ynab","financ"), "card"),
    (("router","gateway","home network","whole home","every device","omada","unifi","whole house"), "router"),
    (("dns","encrypted dns","doh","wifi","wi-fi","public wifi","isp"), "wifi"),
    (("track","tracker","surveil","watch","spy","incognito","fingerprint","profil","ad id","advertising id","acr","smart tv","cookie"), "eye"),
    (("shield","protect","safe","ad block","adblock","block","parental","kids","scam"), "shield"),
    (("password","lock","encrypt","zero-log","no log","no-log","vpn","secure","private","privacy"), "padlock"),
]

def pick_illo(text):
    t = (text or "").lower()
    for keys, key in ILLO_MAP:
        if any(k in t for k in keys):
            return key
    return None

# topic -> clay CHARACTER (people figures) for the character-first layouts. First
# keyword hit wins; only fires on human/benefit themes so most posts still use the
# object illustrations. STANDING figures can run off the bottom edge (bleed),
# seated ones cannot. Assets: char-shield/char-phone (standing), char-laptop/char-calm (seated).
CHAR_MAP = [
    (("family","families","kids","parental","household","loved ones","whole family",
      "your family","for your family"), "char-shield"),
    (("resume","career","job search","cover letter","budget","freelanc","side hustle",
      "your money","financial"), "char-laptop"),
    (("people search","data broker","masked email","for sale online","robocall",
      "spam call","caller id","reverse phone"), "char-phone"),
    (("calm","peace of mind","relax","breathe","mindful","stress","less stress","at ease",
      "slow down","unplug"), "char-calm"),
]
CHAR_STANDING = {"char-phone", "char-shield"}

def pick_char(text):
    t = (text or "").lower()
    for keys, key in CHAR_MAP:
        if any(k in t for k in keys):
            return key
    return None

# AI-rendered clay illustrations (transparent PNGs) composited into the cards.
import base64 as _b64
ILLO_DIR = Path("/home/ubuntu/harbor-design-system/assets/card-engine-illos")
_illo_cache = {}
def _illo_uri(key):
    if key in _illo_cache:
        return _illo_cache[key]
    p = ILLO_DIR / (str(key) + ".png")
    uri = ("data:image/png;base64," + _b64.b64encode(p.read_bytes()).decode()) if p.exists() else None
    _illo_cache[key] = uri
    return uri

def place_illo(key, cx, cy, side):
    """Composite a clay PNG illustration centered at (cx,cy), fit into a side x side
    box. Shadow is baked into the PNG, so no extra SVG filter."""
    uri = _illo_uri(key)
    if not uri:
        return ""
    return (f'<image xlink:href="{uri}" x="{cx-side/2}" y="{cy-side/2}" '
            f'width="{side}" height="{side}" preserveAspectRatio="xMidYMid meet"/>')

# A character theme may have several pose variants on disk (char-shield.png,
# char-shield-2.png, ...). Resolve the set so the engine can rotate them for variety.
_char_variants_cache = {}
def char_variants(base):
    if base not in _char_variants_cache:
        files = sorted(ILLO_DIR.glob(f"{base}.png")) + sorted(ILLO_DIR.glob(f"{base}-*.png"))
        _char_variants_cache[base] = [p.stem for p in files] or [base]
    return _char_variants_cache[base]


# ── base + layouts ───────────────────────────────────────────────────────────
DEFS = (f'<defs>'
        f'<filter id="soft" x="-30%" y="-30%" width="160%" height="170%">'
        f'<feGaussianBlur in="SourceAlpha" stdDeviation="16" result="b"/>'
        f'<feOffset in="b" dx="0" dy="16" result="o"/>'
        f'<feComponentTransfer in="o" result="s"><feFuncA type="linear" slope="0.20"/></feComponentTransfer>'
        f'<feMerge><feMergeNode in="s"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
        f'<linearGradient id="tealgrad" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="#2c7280"/><stop offset="1" stop-color="#194f5d"/></linearGradient>'
        f'</defs>')

def _base(extra=""):
    verts = "".join(f'<line x1="{x}" y1="0" x2="{x}" y2="{H}" stroke="{LINE}" stroke-width="2"/>' for x in range(120,W,120))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 {W} {H}">{DEFS}'
            f'<rect width="{W}" height="{H}" fill="{BG}"/><g opacity="0.08">{verts}</g>{extra}')

def _serif_lines(text,x,y,fs,lh,fill=INK,anchor="start"):
    width=max(8,int(20*(62/fs)))
    lines=textwrap.wrap(text,width=width)[:4] or [text]
    return ("".join(f'<text x="{x}" y="{y+i*lh}" font-family="DM Serif Display, Georgia, serif" '
            f'font-size="{fs}" fill="{fill}" text-anchor="{anchor}">{html.escape(l)}</text>'
            for i,l in enumerate(lines)), len(lines))

def _soft(g):
    return f'<g filter="url(#soft)">{g}</g>'

def _para(text, x, y, fs, *, fill=GREEN, anchor="start", weight="600", maxlines=2):
    """Render a subhead/deck wrapped to <=maxlines lines so real sentences never
    overflow the card. Ellipsizes if it would run longer."""
    text = (text or "").strip()
    if not text:
        return ""
    cpl = max(12, int(880 / (fs * 0.60)))      # conservative: semibold DM Sans is wide
    lines = textwrap.wrap(text, width=cpl)
    if len(lines) > maxlines:
        lines = lines[:maxlines]
        lines[-1] = lines[-1].rstrip(".,;: ") + "…"
    lh = int(fs * 1.28)
    return "".join(f'<text x="{x}" y="{y+i*lh}" font-family="DM Sans, sans-serif" font-size="{fs}" '
                   f'fill="{fill}" font-weight="{weight}" text-anchor="{anchor}">{html.escape(l)}</text>'
                   for i, l in enumerate(lines))

def layout_bigtype(head,sub,eyebrow,url):
    deco=papergrid()+blob(132,H-138,1.0,SAGE,0.55)+dotgrid(92,H-188,4,3,color=GREEN,op=0.3)+plusmark(W-140,230,16)
    hsvg,n=_serif_lines(head,80,438,134,150); sub_y=438+n*150+40
    return _base(f'''{deco}
      <text x="80" y="250" font-family="DM Mono, monospace" font-size="26" fill="{TEAL}" letter-spacing="6">{html.escape(eyebrow)}</text>
      {hsvg}{_para(sub,80,sub_y,44,anchor="start")}
      <text x="80" y="{H-70}" font-family="DM Mono, monospace" font-size="24" fill="{TEAL}" letter-spacing="2">{html.escape(url)}</text>''')+"</svg>"

def layout_hero(head,sub,eyebrow,url,key):
    deco=(dotgrid(78,94,3,3,color=SAGE,op=0.3)+dotgrid(W-138,94,3,3,color=SAGE,op=0.3)
          +blob(W-36,H-46,0.8,SAGE,0.3)+plusmark(96,H-150,13))
    hsvg,n=_serif_lines(head,W//2,308,98,100,anchor="middle")
    # center the illustration in the gap between the headline and the subhead so
    # tall (3-4 line) headlines never collide with it
    h_bottom=308+(n-1)*100+60
    cy=int((h_bottom+(H-210))/2)
    art=place_illo(key,W//2,cy,520)
    return _base(f'''{deco}{hsvg}{art}
      {_para(sub,W//2,H-150,40,anchor="middle")}
      <text x="{W//2}" y="{H-58}" font-family="DM Mono, monospace" font-size="22" fill="{TEAL}" letter-spacing="2" text-anchor="middle">{html.escape(url)}</text>''')+"</svg>"

def layout_object(head,sub,eyebrow,url,key):
    # left-aligned brand serif headline + clay hero illustration, placed in the
    # space remaining below the headline+subhead so tall headlines never collide
    hsvg,n=_serif_lines(head,80,222,104,110)
    h_bottom=222+(n-1)*110+40
    sub_y=h_bottom+58
    sub_bottom=sub_y+102            # up to 2 wrapped subhead lines
    cy=int((sub_bottom+40+(H-120))/2)
    art=place_illo(key,W//2,cy,480)
    return _base(f'''{hsvg}
      {_para(sub,80,sub_y,40,anchor="start")}
      {art}
      <text x="80" y="{H-70}" font-family="DM Mono, monospace" font-size="24" fill="{TEAL}" letter-spacing="2">{html.escape(url)}</text>''')+"</svg>"


# ── character-first layouts (clay PEOPLE figures, not objects) ────────────────
def _eyebrow(x, y, text, fill=TEAL, anchor="start"):
    return (f'<text x="{x}" y="{y}" font-family="DM Mono, monospace" font-size="25" '
            f'fill="{fill}" letter-spacing="6" text-anchor="{anchor}">{html.escape((text or "").upper())}</text>')

def layout_bleed(head, sub, eyebrow, url, key):
    # large standing figure anchored to the bottom-right, running off the edge;
    # headline + subhead top-left, url stays clear in the bottom-left
    deco = (papergrid() + dotgrid(80, 96, 3, 3, color=SAGE, op=0.3)
            + plusmark(W - 120, 250, 15) + blob(120, 360, 1.1, SAGE, 0.30))
    hsvg, n = _serif_lines(head, 80, 300, 92, 100)
    sub_y = 300 + (n - 1) * 100 + 64
    art = place_illo(key, int(W * 0.58), H - 120, 1060)
    return _base(f'''{deco}
      {_eyebrow(80, 200, eyebrow)}
      {hsvg}
      {_para(sub, 80, sub_y, 38, anchor="start")}
      {art}
      <text x="80" y="{H-60}" font-family="DM Mono, monospace" font-size="22" fill="{TEAL}"
            letter-spacing="2">{html.escape(url)}</text>''') + "</svg>"

def layout_sidekick(head, sub, eyebrow, url, key):
    # magazine split: serif headline + subhead in the left column, figure on a
    # soft sage panel on the right. Subhead is wrapped narrow so it never runs
    # under the figure.
    deco = dotgrid(W - 120, H - 150, 3, 3, color=SAGE, op=0.3) + plusmark(96, 150, 14)
    panel = (f'<path d="M620 0 H{W} V{H} H760 C 640 {H}, 560 {int(H*0.62)}, 600 {int(H*0.42)} '
             f'C 632 {int(H*0.26)}, 600 110, 620 0 Z" fill="{SAGE}" opacity="0.35"/>')
    lines = textwrap.wrap(head, width=14)[:4] or [head]
    hsvg = "".join(f'<text x="80" y="{300+i*92}" font-family="DM Serif Display, Georgia, serif" '
                   f'font-size="84" fill="{INK}">{html.escape(l)}</text>' for i, l in enumerate(lines))
    sub_y = 300 + len(lines) * 92 + 30
    art = place_illo(key, W - 290, H // 2 + 150, 760)
    sublines = textwrap.wrap(sub or "", width=22)[:3]
    subsvg = "".join(f'<text x="80" y="{sub_y+i*46}" font-family="DM Sans, sans-serif" '
                     f'font-size="36" fill="{GREEN}" font-weight="600">{html.escape(l)}</text>'
                     for i, l in enumerate(sublines))
    return _base(f'''{panel}{deco}{art}
      {_eyebrow(82, 200, eyebrow)}
      {hsvg}
      {subsvg}
      <text x="80" y="{H-70}" font-family="DM Mono, monospace" font-size="22" fill="{TEAL}"
            letter-spacing="2">{html.escape(url)}</text>''') + "</svg>"

def layout_spotlight(head, sub, eyebrow, url, key):
    # figure on a rounded sage "stage" + floor ellipse, centered headline above.
    # The stage is placed ADAPTIVELY below the headline so tall headlines never
    # collide with it, and the figure scales to the stage height.
    deco = dotgrid(80, 96, 3, 3, color=SAGE, op=0.3) + dotgrid(W - 140, 96, 3, 3, color=SAGE, op=0.3)
    hsvg, n = _serif_lines(head, W // 2, 300, 88, 94, anchor="middle")
    stage_top = max(458, 300 + (n - 1) * 94 + 64)
    stage_bottom = H - 210
    stage_h = max(360, stage_bottom - stage_top)
    stage_cy = stage_top + stage_h // 2
    stage = (f'<rect x="150" y="{stage_top}" width="{W-300}" height="{stage_h}" rx="60" '
             f'fill="{SAGE}" opacity="0.45"/>'
             f'<ellipse cx="{W//2}" cy="{stage_bottom-70}" rx="250" ry="46" fill="{DARK}" opacity="0.12"/>')
    art = place_illo(key, W // 2, stage_cy, min(560, stage_h - 80))
    return _base(f'''{deco}
      {_eyebrow(W//2, 200, eyebrow, anchor="middle")}
      {hsvg}{stage}{art}
      {_para(sub, W//2, H-150, 38, anchor="middle")}
      <text x="{W//2}" y="{H-60}" font-family="DM Mono, monospace" font-size="22" fill="{TEAL}"
            letter-spacing="2" text-anchor="middle">{html.escape(url)}</text>''') + "</svg>"


def build_svg(headline, subhead, eyebrow, url, seed=""):
    """Pick layout + illustration deterministically and return the SVG string."""
    headline = (headline or "").strip()
    n = int(hashlib.md5((seed or headline).encode()).hexdigest(), 16)

    # Character-first layouts: when a focused human/benefit theme matches and the
    # clay figure exists, use a character card for ~half of those posts (n%2 gate
    # keeps objects dominant), rotating through the 3 new formats. The other half
    # fall through to the object/big-type path below.
    char = pick_char(f"{eyebrow} {headline} {subhead}")
    if char and _illo_uri(char) and n % 2 == 0:
        layouts = [layout_spotlight, layout_sidekick]
        if char in CHAR_STANDING:
            layouts = [layout_bleed, layout_sidekick, layout_spotlight]
        variants = char_variants(char)            # rotate pose variants for variety
        art_key = variants[(n // 100) % len(variants)]
        return layouts[(n // 2) % len(layouts)](headline, subhead, eyebrow, url, art_key)

    key = pick_illo(f"{eyebrow} {headline} {subhead}")
    if key and not _illo_uri(key):   # mapped but asset missing -> fall back cleanly
        key = None
    if key is None:
        return layout_bigtype(headline, subhead, eyebrow, url)
    if n % 2 == 0 and len(headline) <= 38:
        return layout_object(headline, subhead, eyebrow, url, key)
    return layout_hero(headline, subhead, eyebrow, url, key)


def render(stem, *, brand="harbor", headline="", subhead="", eyebrow="", url="", topic="", out_dir):
    """Render one card to <out_dir>/<stem>.{svg,png} (1080x1350). Returns png Path."""
    svg = build_svg(headline, subhead, eyebrow, url, seed=stem)
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    svgp = out/(stem+".svg"); pngp = out/(stem+".png")
    svgp.write_text(svg)
    subprocess.run(["rsvg-convert","-w",str(W),"-h",str(H),str(svgp),"-o",str(pngp)],
                   check=True, timeout=40)
    return pngp


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
    for stem, brand, head, sub, eb, url in [
        ("smoke_broker","scan","You are for sale online","Data brokers list your whole profile","HARBOR / SCAN","scan.harborprivacy.com"),
        ("smoke_dns","harbor","Your router is leaking","Encrypted DNS for the whole house","HARBOR / PRIVACY","harborprivacy.com"),
        ("smoke_career","career","Your resume is not a product","Stop paying twice for help","HARBOR / CAREER","harborprivacy.com/career"),
        ("smoke_money","money","Budget without your bank login","Private by design, never sold","HARBOR / MONEY","harborprivacy.com/money"),
    ]:
        p = render(stem, brand=brand, headline=head, subhead=sub, eyebrow=eb, url=url, topic=head, out_dir=d)
        print("wrote", p)
