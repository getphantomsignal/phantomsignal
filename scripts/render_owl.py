#!/usr/bin/env python3
"""
Render the OwlScan ASCII owl art to PNG assets.

Outputs two files:
  owlscan/web/static/img/owl-ascii.png             — dark background version
  owlscan/web/static/img/owl-ascii-transparent.png — transparent background (used in UI)

Requirements:
  pip install Pillow
  apt-get install fonts-hack  (or equivalent — needs Hack-Regular.ttf)

Usage:
  python scripts/render_owl.py
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# ── ASCII art ────────────────────────────────────────────────────────────────
OWL_LINES = [
    "                    ~o88ooooooooooooo88o~",
    "               ouooooo,~oo         oo~,ooooouo",
    "               8     ~88888.     ,88888~     8",
    "               8      go===os   go===os      8",
    "               8    ,8`     '8_8`     '8.    8",
    "               8    8`\\ ~~~ /'8`\\ ~~~ /'8    8",
    "               8    8   =@=   8   =@=   8    8",
    "               8    8i       /8\\       i8    8",
    "               8     8s     g8 8s     s8     8",
    "               8      dooooo`8_8'ooooob      8",
    "               8     d!      'Y`      !b     8",
    "               8     8        ~        8     8",
    "               8     8                 8     8",
    "               8   ] 8                 8 [   8",
    "               8 [ ] 8                 8 [ ] 8",
    "               8 [ ] !8               8| [ ] 8",
    "               8 [ ]s88b-oo- !!! -oo-d88s[ ] 8",
    "               8 [,88  8i'`   ~   '`i8  88.] 8",
    "               8 88`   88s'88` '88`gf8   '88 8",
    "               888   ,g8s/8. ooo ,8\\g8s.   888",
    "               88`  i888888fo_X_of888888i  '88",
    "               V    YY'`~'`  ~~~  '` ~ YY    V",
    '                    ""     OwlScan    ""',
]

# ── Config ───────────────────────────────────────────────────────────────────
OWL_SZ  = 14                        # px — Hack Regular for ASCII art
LINE_H  = OWL_SZ + 2               # line spacing
PAD     = 16                        # canvas padding (px)
FG      = (0, 255, 65, 255)         # neon green
DARK_BG = (10, 10, 15, 255)         # near-black

FONT_PATH = "/usr/share/fonts/truetype/hack/Hack-Regular.ttf"

OUT_DIR = Path(__file__).parent.parent / "owlscan" / "web" / "static" / "img"

# ── Render ───────────────────────────────────────────────────────────────────
def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        font = ImageFont.truetype(FONT_PATH, OWL_SZ)
    except OSError:
        raise SystemExit(
            f"Font not found: {FONT_PATH}\n"
            "Install with: sudo apt-get install fonts-hack\n"
            "or update FONT_PATH in this script."
        )

    # Measure canvas
    dummy = Image.new("RGBA", (1, 1))
    dc    = ImageDraw.Draw(dummy)
    max_w = max(dc.textlength(l, font=font) for l in OWL_LINES)
    art_h = LINE_H * len(OWL_LINES)

    total_w = int(max_w + PAD * 2)
    total_h = int(PAD + art_h + PAD)
    art_x   = (total_w - max_w) / 2   # centre art horizontally

    def render(bg: tuple, fg: tuple, path: Path) -> None:
        img = Image.new("RGBA", (total_w, total_h), bg)
        d   = ImageDraw.Draw(img)
        y   = PAD
        for line in OWL_LINES:
            d.text((art_x, y), line, font=font, fill=fg)
            y += LINE_H
        img.save(path)
        print(f"  ✓  {path}  ({total_w}×{total_h})")

    print("Rendering OwlScan owl assets...")
    render(DARK_BG, FG, OUT_DIR / "owl-ascii.png")
    render((0, 0, 0, 0), FG, OUT_DIR / "owl-ascii-transparent.png")
    print("Done.")


if __name__ == "__main__":
    main()
