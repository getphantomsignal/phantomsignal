#!/usr/bin/env python3
"""
Render the PhantomSignal Gravatar avatar.

"PS" in doom ASCII art with HUD-style decorations:
  - scanline background
  - corner [+] markers
  - dashed top/bottom rule lines
  - // PHANTOM SIGNAL // label

Output: docs/assets/phantomsignal-gravatar.png

Requirements: pip install Pillow pyfiglet
Usage:        python scripts/render_gravatar.py
"""

from pathlib import Path
import pyfiglet
from PIL import Image, ImageDraw, ImageFilter, ImageFont

FONT_PATH   = "/usr/share/fonts/truetype/hack/Hack-Regular.ttf"
CANVAS      = 512
TARGET_FRAC = 0.76      # doom PS fills 76% of canvas width

GREEN       = (0, 255, 65, 255)
GREEN_DIM   = (0, 180, 45, 180)
DARK_BG     = (10, 10, 15, 255)

ROOT = Path(__file__).parent.parent
OUT  = ROOT / "docs" / "assets" / "phantomsignal-gravatar.png"


# ── helpers ──────────────────────────────────────────────────────────────────

def load_font(size: int) -> ImageFont.FreeTypeFont:
    try:
        return ImageFont.truetype(FONT_PATH, size)
    except OSError:
        return ImageFont.load_default()


def measure(lines: list[str], font) -> tuple[int, int]:
    dummy = Image.new("RGBA", (1, 1))
    dc = ImageDraw.Draw(dummy)
    w = int(max(dc.textlength(l, font=font) for l in lines))
    h = len(lines) * (font.size + max(2, font.size // 6))
    return w, h


def fit_font_size(lines: list[str], target_px: float) -> int:
    lo, hi, best = 8, 120, 8
    for sz in range(lo, hi + 1):
        font = load_font(sz)
        w, _ = measure(lines, font)
        if w <= target_px:
            best = sz
        else:
            break
    return best


def glow_composite(base: Image.Image, layer: Image.Image,
                   r1: int, r2: int) -> Image.Image:
    g1 = layer.filter(ImageFilter.GaussianBlur(radius=r1))
    g2 = layer.filter(ImageFilter.GaussianBlur(radius=r2))
    out = Image.alpha_composite(base, g2)
    out = Image.alpha_composite(out, g1)
    out = Image.alpha_composite(out, layer)
    return out


# ── scanlines ────────────────────────────────────────────────────────────────

def draw_scanlines(img: Image.Image, spacing: int = 4, alpha: int = 18) -> Image.Image:
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    dc = ImageDraw.Draw(overlay)
    for y in range(0, img.height, spacing):
        dc.line([(0, y), (img.width, y)], fill=(0, 0, 0, alpha))
    return Image.alpha_composite(img, overlay)


# ── HUD decorations ───────────────────────────────────────────────────────────

def draw_hud(canvas_img: Image.Image) -> Image.Image:
    """Corner [+] markers, dashed rules, and bottom label."""
    C = CANVAS
    hud = Image.new("RGBA", (C, C), (0, 0, 0, 0))
    dc  = ImageDraw.Draw(hud)

    sm_font  = load_font(13)   # corner markers + rules
    lbl_font = load_font(11)   # bottom label

    pad = 18   # distance from edge for corners

    # corner [+] markers
    corners = [(pad, pad), (C - pad, pad), (pad, C - pad), (C - pad, C - pad)]
    for cx, cy in corners:
        text = "[+]"
        dummy = Image.new("RGBA", (1, 1))
        d2 = ImageDraw.Draw(dummy)
        tw = int(d2.textlength(text, font=sm_font))
        th = sm_font.size
        # anchor to corner quadrant
        x = cx if cx < C // 2 else cx - tw
        y = cy if cy < C // 2 else cy - th
        dc.text((x, y), text, font=sm_font, fill=GREEN_DIM)

    # dashed rule — top and bottom
    dash = "─" * 28
    dummy = Image.new("RGBA", (1, 1))
    d2 = ImageDraw.Draw(dummy)
    dw = int(d2.textlength(dash, font=sm_font))
    rule_x = (C - dw) // 2

    rule_top_y = pad + sm_font.size + 6
    rule_bot_y = C - pad - sm_font.size - 6 - sm_font.size

    dc.text((rule_x, rule_top_y), dash, font=sm_font, fill=GREEN_DIM)
    dc.text((rule_x, rule_bot_y), dash, font=sm_font, fill=GREEN_DIM)

    # bottom label
    label = "// PHANTOM SIGNAL //"
    lw = int(d2.textlength(label, font=lbl_font))
    dc.text(((C - lw) // 2, C - pad - lbl_font.size), label,
            font=lbl_font, fill=GREEN_DIM)

    # apply glow to HUD layer
    hud_glow = hud.filter(ImageFilter.GaussianBlur(radius=3))
    out = Image.alpha_composite(canvas_img, hud_glow)
    out = Image.alpha_composite(out, hud)
    return out


# ── main render ───────────────────────────────────────────────────────────────

def render() -> None:
    raw   = pyfiglet.figlet_format("PS", font="doom")
    lines = [l.rstrip() for l in raw.rstrip().splitlines() if l.strip()]

    font_sz = fit_font_size(lines, CANVAS * TARGET_FRAC)
    font    = load_font(font_sz)
    line_h  = font_sz + max(2, font_sz // 6)

    text_w, _ = measure(lines, font)
    text_h    = len(lines) * line_h

    # text layer
    text_layer = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    td = ImageDraw.Draw(text_layer)
    x0 = (CANVAS - text_w) // 2
    y0 = (CANVAS - text_h) // 2
    for i, line in enumerate(lines):
        td.text((x0, y0 + i * line_h), line, font=font, fill=GREEN)

    # compose: dark bg → glow → text
    base = Image.new("RGBA", (CANVAS, CANVAS), DARK_BG)
    img  = glow_composite(base, text_layer, r1=6, r2=18)

    # scanlines
    img = draw_scanlines(img, spacing=4, alpha=20)

    # HUD decorations
    img = draw_hud(img)

    # flatten to RGB
    final = Image.new("RGB", (CANVAS, CANVAS), DARK_BG[:3])
    final.paste(img, mask=img.split()[3])

    OUT.parent.mkdir(parents=True, exist_ok=True)
    final.save(OUT, "PNG")
    print(f"  ✓  {OUT}  ({CANVAS}×{CANVAS}  font_sz={font_sz})")


if __name__ == "__main__":
    print("Rendering PhantomSignal Gravatar avatar...")
    render()
    print("Done.")
