#!/usr/bin/env python3
"""One-off Harbor Blocker ad/social card: 'every link rats you out' before/after.
Reuses card_engine's palette + fonts for brand consistency. Not part of the
build_svg rotation (this is a bespoke literal before/after, not a general
post template) -- rerun this script directly to regenerate.
"""
import html, subprocess
from pathlib import Path
import card_engine as ce

W, H = ce.W, ce.H
BG, INK, MUTE, TEAL, GREEN, LINE = ce.BG, ce.INK, ce.MUTE, ce.TEAL, ce.GREEN, ce.LINE
DANGER = "#a64a40"
DANGER_SOFT = "rgba(166,74,64,0.07)"
TEAL_SOFT = "rgba(31,93,107,0.07)"

def xmark(cx, cy, r=15):
    return (f'<path d="M{cx-r} {cy-r} L{cx+r} {cy+r} M{cx+r} {cy-r} L{cx-r} {cy+r}" '
            f'stroke="{DANGER}" stroke-width="5" stroke-linecap="round"/>')

def check_path(cx, cy):
    return (f'<path d="M{cx-16} {cy} l13 14 l24 -30" stroke="{GREEN}" stroke-width="7" '
            f'fill="none" stroke-linecap="round" stroke-linejoin="round"/>')

def panel(y, h, *, border, fill, label, label_fill, icon_svg, bar_content, caption, caption_fill):
    return f'''
    <rect x="80" y="{y}" width="920" height="{h}" rx="18" fill="{fill}" stroke="{border}" stroke-width="2"/>
    <text x="112" y="{y+48}" font-family="DM Mono, monospace" font-size="22" fill="{label_fill}"
          letter-spacing="3">{html.escape(label)}</text>
    {icon_svg}
    <rect x="112" y="{y+68}" width="856" height="66" rx="33" fill="#ffffff" stroke="{LINE}" stroke-width="2"/>
    {bar_content}
    <text x="112" y="{y+h-34}" font-family="DM Mono, monospace" font-size="23" fill="{caption_fill}">{html.escape(caption)}</text>
    '''

def build():
    eyebrow = ce._eyebrow(80, 150, "HARBOR BLOCKER")
    headline = (
        f'<text x="80" y="272" font-family="DM Serif Display, Georgia, serif" font-size="76" fill="{INK}">Every link you click</text>'
        f'<text x="80" y="364" font-family="DM Serif Display, Georgia, serif" font-size="76" fill="{INK}">rats you out.</text>'
    )

    before_bar = (
        f'<text x="140" y="{430+68+43}" font-family="DM Mono, monospace" font-size="22">'
        f'<tspan fill="{INK}">shop.com/deal?</tspan>'
        f'<tspan fill="{DANGER}" font-weight="700">ref=you23&amp;fbclid=IwAR3x9k&amp;utm_source=friend</tspan>'
        f'</text>'
    )
    before = panel(420, 220, border=DANGER, fill=DANGER_SOFT, label="BEFORE",
                   label_fill=DANGER, icon_svg=xmark(958, 450),
                   bar_content=before_bar,
                   caption="Tells them exactly who sent you, and where.",
                   caption_fill=DANGER)

    after_bar = (
        f'<text x="140" y="{680+68+43}" font-family="DM Mono, monospace" font-size="28" fill="{INK}" font-weight="500">'
        f'shop.com/deal</text>'
    )
    after = panel(680, 220, border=TEAL, fill=TEAL_SOFT, label="AFTER: HARBOR BLOCKER ON",
                  label_fill=TEAL, icon_svg=check_path(958, 710),
                  bar_content=after_bar,
                  caption="Nothing. Stripped before it leaves your browser.",
                  caption_fill=TEAL)

    cta_text = "ADD TO CHROME · FREE"
    pw = 60 + len(cta_text) * 17
    cta = (f'<g transform="translate(80,980)">'
           f'<rect width="{pw}" height="80" rx="40" fill="#e0a63c"/>'
           f'<text x="{pw/2}" y="51" text-anchor="middle" font-family="DM Sans, sans-serif" '
           f'font-size="26" font-weight="700" fill="#1a1206" letter-spacing="1">{html.escape(cta_text)}</text></g>')
    sub_cta = (f'<text x="{80+pw+30}" y="1030" font-family="DM Mono, monospace" font-size="21" '
               f'fill="{MUTE}">No account.<tspan x="{80+pw+30}" dy="28">No subscription.</tspan></text>')

    footer = (
        f'<text x="80" y="1180" font-family="DM Mono, monospace" font-size="21" fill="{MUTE}" '
        f'letter-spacing="2">CHROME NOW · EDGE COMING SOON</text>'
        f'<text x="80" y="1230" font-family="DM Mono, monospace" font-size="28" fill="{TEAL}" '
        f'font-weight="700" letter-spacing="1">harborprivacy.com/blocker</text>'
    )

    verts = "".join(f'<line x1="{x}" y1="0" x2="{x}" y2="{H}" stroke="{LINE}" stroke-width="2"/>' for x in range(120, W, 120))
    content = f'<g opacity="0.06">{verts}</g>' + eyebrow + headline + before + after + cta + sub_cta + footer
    return ce._base_color(BG, content) + "</svg>"

def main():
    out_dir = Path("/home/ubuntu/harbor-design-system/assets/social")
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = "blocker-links-rat-you-out"
    svg_path = out_dir / f"{stem}.svg"
    png_path = out_dir / f"{stem}.png"
    svg_path.write_text(build())
    subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), str(svg_path), "-o", str(png_path)],
                    check=True, timeout=40)
    print(png_path)

if __name__ == "__main__":
    main()
