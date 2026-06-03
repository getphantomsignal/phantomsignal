#!/usr/bin/env python3
"""
PhantomSignal ANSI Art Pack
BBS / Blocktronics / Demoscene aesthetic — 80-col CP437 palette
Generates:
  docs/assets/phantom_scene.ans   — full 80-col scene
  docs/assets/phantom_ghost.ans   — standalone ghost figure
  docs/assets/phantom_splash.ans  — 80x24 CLI splash
"""
from pathlib import Path
import sys

E = "\033"
RST = f"{E}[0m"
_ = RST  # shorthand used in multiline art strings

# ── colour primitives ────────────────────────────────────────────────────────
def f(n):  return f"{E}[{30+n if n<8 else 90+n-8}m"
def b(n):  return f"{E}[{40+n if n<8 else 100+n-8}m"
def fb(fg, bg): return f"{E}[{30+fg if fg<8 else 90+fg-8};{40+bg if bg<8 else 100+bg-8}m"

K,R,G,Y,B,M,C,W = 0,1,2,3,4,5,6,7
bK,bR,bG,bY,bB,bM,bC,bW = 8,9,10,11,12,13,14,15

# Named shortcuts
GN  = f(G);   BGN = f(bG)   # green / bright green
CY  = f(C);   BCY = f(bC)   # cyan  / bright cyan
MG  = f(M);   BMG = f(bM)   # mag   / bright magenta
WH  = f(bW);  DM  = f(W)    # white / dim grey
BLK = b(K)                   # black bg
YW  = f(bY)                  # yellow

# half-block helpers — top half = FG, bottom half = BG
def HT(fg, bg): return fb(fg, bg) + "▀" + RST   # upper half fg, lower half bg
def HB(fg, bg): return fb(fg, bg) + "▄" + RST   # lower half fg, upper half bg

DOCS = Path(__file__).parent.parent / "docs" / "assets"
DOCS.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
#  GHOST FIGURE  (24 wide, 17 tall)
#  Half-block dome, shade-block body, magenta eyes, green tentacles
# ─────────────────────────────────────────────────────────────────────────────
def ghost_lines():
    """Returns list of raw ANSI strings, each exactly 24 printable chars wide."""
    _ = RST
    cD = CY        # dim cyan (outer glow)
    cB = BCY       # bright cyan (solid body)
    cS = f(bC)     # shade layer  (same as bright cyan — use blocks to vary)
    mg = BMG       # bright magenta (eyes)
    gn = BGN       # signal green
    dk = f(bK)     # dark grey (inner shade)
    wh = WH

    # Each row: list of (text, colour) segments — assembled left-to-right
    # Pad/trim to ensure 24 printable chars per row
    rows = [
        # row 0 — dome top
        f"   {HB(bC,K)}{HB(bC,K)}{cB}████████████{_}{HB(bC,K)}{HB(bC,K)}   ",
        # row 1 — dome
        f"  {cB}████████████████████  {_}",
        # row 2 — upper body
        f"  {cB}███{CY}▓▓▓▓▓▓▓▓▓▓▓▓▓{cB}███  {_}",
        # row 3 — eye row top
        f"  {cB}██{CY}▓▓{_}{cB}██████  ██████{CY}▓▓{cB}██  {_}",
        # row 4 — eyes (bright magenta on cyan)
        f"  {cB}██{CY}▓{fb(bM,bC)}  ◉ ◉  {fb(bM,bC)}  ◉ ◉  {CY}▓{cB}██  {_}",
        # row 5 — eye row bottom
        f"  {cB}██{CY}▓▓{cB}██████  ██████{CY}▓▓{cB}██  {_}",
        # row 6 — mouth / expression
        f"  {cB}██{CY}▓▓▓{dk}  · · · · · ·  {CY}▓▓▓{cB}██  {_}",
        # row 7 — waist
        f"  {cB}███{CY}▓▓▓▓▓▓▓▓▓▓▓▓▓{cB}███  {_}",
        # row 8 — lower body
        f"  {cB}████████████████████  {_}",
        # row 9 — scallop top
        f"  {cB}███{HT(bC,K)}██{HT(bC,K)}███{HT(bC,K)}██{HT(bC,K)}███{cB}███  {_}",
        # row 10 — scallop bottom / tentacle start
        f"   {HT(bC,K)}{HT(bC,K)} {HT(bC,K)}{HT(bC,K)} {HT(bC,K)}{HT(bC,K)} {HT(bC,K)}{HT(bC,K)}   ",
        # row 11 — tentacles
        f"   {cB}▌{_}    {cB}▌{_}    {cB}▌{_}    {cB}▌{_}   ",
        # row 12 — tentacle tips fade
        f"   {CY}▌{_}    {CY}▌{_}    {CY}▌{_}    {CY}▌{_}   ",
        # row 13 — ghost signal emission at base
        f"   {gn}·{_}    {gn}·{_}    {gn}·{_}    {gn}·{_}   ",
    ]
    return rows


# ─────────────────────────────────────────────────────────────────────────────
#  SIGNAL HALO  — concentric rings around the ghost
#  Returns a list of (left_pad, halo_left, ghost_row, halo_right, right_pad)
# ─────────────────────────────────────────────────────────────────────────────
HALO = [
    # (inner_ring, outer_ring) per ghost row
    #  ring chars: ░ ▒ · ─ space
    #  colour:     cB  CY  gn  GN  BLK
    (f"{CY}░░{_}", f"{GN}· ·{_}"),
    (f"{CY}░░{_}", f"{GN}·  ·{_}"),
    (f"{CY}░░{_}", f"{GN}·   {_}"),
    (f"{CY}░░{_}", f"{GN}─   {_}"),
    (f"{CY}░░{_}", f"{GN}─   {_}"),
    (f"{CY}░░{_}", f"{GN}─   {_}"),
    (f"{CY}░░{_}", f"{GN}─   {_}"),
    (f"{CY}░░{_}", f"{GN}─   {_}"),
    (f"{CY}░░{_}", f"{GN}─   {_}"),
    (f"{CY}░░{_}", f"{GN}─   {_}"),
    (f"{CY}░░{_}", f"{GN}·   {_}"),
    (f"{CY}░{_} ", f"{GN}·  ·{_}"),
    (f"{CY}░{_} ", f"{GN}· · {_}"),
    ("  ",         "    "),
]


# ─────────────────────────────────────────────────────────────────────────────
#  FULL SCENE (80 cols)
# ─────────────────────────────────────────────────────────────────────────────
def scene() -> str:
    lines = []
    R = RST

    def ln(s=""): lines.append(s)

    # ── border ──
    bdr = f"{CY}║{R}"
    top = f"{CY}╔{'═'*78}╗{R}"
    bot = f"{CY}╚{'═'*78}╝{R}"
    mid = f"{CY}╠{'═'*78}╣{R}"

    ln(top)

    # ── title block ──
    def trow(s): ln(f"{bdr}  {BCY}{s:<76}{R}{bdr}")

    ln(f"{bdr}{'':^80}{bdr}")
    trow(f"{BCY}    ____  __  _____    _   ____________  __  ___")
    trow(f"{BCY}   / __ \\/ / / /   |  / | / /_  __/ __ \\/  |/  /")
    trow(f"{CY}  / /_/ / /_/ / /| | /  |/ / / / / / / / /|_/ /")
    trow(f"{CY} / ____/ __  / ___ |/ /|  / / / / /_/ / /  / /")
    trow(f"{f(bK)}/_/   /_/ /_/_/  |_/_/ |_/ /_/  \\____/_/  /_/{R}")
    ln(f"{bdr}{'':^80}{bdr}")
    trow(f"{BCY}   _____ ___________   _____    __")
    trow(f"{BCY}  / ___//  _/ ____/ | / /   |  / /")
    trow(f"{CY}  \\__ \\ / // / __/  |/ / /| | / /")
    trow(f"{CY} ___/ // // /_/ / /|  / ___ |/ /___")
    trow(f"{f(bK)}/____/___/\\____/_/ |_/_/  |_/_____/{R}")
    ln(f"{bdr}{'':^80}{bdr}")

    # ── signal divider ──
    sig_div = (
        f"{GN}·{R}  {GN}·{R}  {GN}─{R}"
        + f"{BGN}{'─'*52}{R}"
        + f"{GN}─{R}  {GN}·{R}  {GN}·{R}"
    )
    ln(f"{bdr}  {sig_div}  {bdr}")
    ln(f"{bdr}{'':^80}{bdr}")

    # ── ghost + halo section ──
    ghost = ghost_lines()
    pad_l = 18   # left padding before halo

    for i, grow in enumerate(ghost):
        if i < len(HALO):
            hl, hr = HALO[i]
        else:
            hl = hr = "    "

        # Build: border + pad + outer_halo + inner_halo + ghost + inner_halo + outer_halo + pad + border
        # We keep it symmetric around the ghost
        row = (
            f"{bdr}"
            f"{'':>{pad_l}}"
            f"{GN}{hr[::-1]}{R}"           # outer ring left (mirrored)
            f"{CY}{hl[::-1]}{R}"           # inner ring left (mirrored)
            f"{grow}"                       # ghost row (24 chars)
            f"{CY}{hl}{R}"                 # inner ring right
            f"{GN}{hr}{R}"                 # outer ring right
            f"{'':>{pad_l}}"
            f"{bdr}"
        )
        ln(row)

    # ── bottom signal divider ──
    ln(f"{bdr}{'':^80}{bdr}")
    ln(f"{bdr}  {sig_div}  {bdr}")
    ln(f"{bdr}{'':^80}{bdr}")

    # ── tagline ──
    tagline = f"{BCY}>> OPEN-SOURCE OSINT INTELLIGENCE FRAMEWORK <<"
    ln(f"{bdr}  {tagline:<76}{R}{bdr}")
    motto    = f'{DM}"See everything. Leave no trace."{R}'
    ln(f"{bdr}  {motto:<76}{R}{bdr}")
    ln(f"{bdr}{'':^80}{bdr}")

    # ── install / repo line ──
    install = f"{BGN}pip install phantomsignal{R}   {DM}github.com/getphantomsignal/phantomsignal{R}"
    ln(f"{bdr}  {install:<76}{R}{bdr}")
    ln(f"{bdr}  {DM}phantomsignal.sh{R:<60}v1.3.0{bdr}")
    ln(f"{bdr}{'':^80}{bdr}")
    ln(bot)

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  STANDALONE GHOST  (compact, embeddable)
# ─────────────────────────────────────────────────────────────────────────────
def standalone_ghost() -> str:
    lines = []
    R = RST
    ghost = ghost_lines()
    gn = BGN

    header = [
        f"  {BCY}P H A N T O M   S I G N A L{R}",
        f"  {GN}{'─'*28}{R}",
        f"  {DM}OSINT Intelligence Framework{R}",
        f"  {GN}{'─'*28}{R}",
        "",
    ]
    for h in header:
        lines.append(h)

    # Signal rings
    ring3 = f"{GN}·  ·  ·  {'─'*14}  ·  ·  ·{R}"
    ring2 = f"{CY}     ░░{'░'*18}░░{R}"

    lines.append(f"  {ring3}")
    lines.append(f"  {ring2}")

    for i, row in enumerate(ghost):
        inner_l = f"{CY}░░{R}"
        inner_r = f"{CY}░░{R}"
        lines.append(f"  {inner_l}{row}{inner_r}")

    lines.append(f"  {ring2}")
    lines.append(f"  {ring3}")
    lines.append("")
    lines.append(f'  {DM}"See everything. Leave no trace."{R}')
    lines.append(f"  {GN}pip install phantomsignal{R}")
    lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  SPLASH SCREEN  (80×24 — fits a standard terminal exactly)
# ─────────────────────────────────────────────────────────────────────────────
def splash() -> str:
    lines = []
    R = RST

    def ln(s=""): lines.append(s)

    bdr = f"{CY}║{R}"
    top = f"{CY}╔{'═'*78}╗{R}"
    bot = f"{CY}╚{'═'*78}╝{R}"

    ln(top)

    # Compact title (2 rows)
    ln(f"{bdr}  {BCY}{'PHANTOM SIGNAL':^76}{R}{bdr}")
    ln(f"{bdr}  {GN}{'OPEN-SOURCE OSINT INTELLIGENCE FRAMEWORK':^76}{R}{bdr}")
    ln(f"{bdr}  {CY}{'─'*76}{R}{bdr}")

    # Ghost rows 0-9 (top half of ghost, centred)
    ghost = ghost_lines()
    for i, row in enumerate(ghost[:10]):
        side_l = f"{GN}{('· ' if i%3==0 else '  ')}{R}{CY}░{R}"
        side_r = f"{CY}░{R}{GN}{(' ·' if i%3==0 else '  ')}{R}"
        pad = " " * 22
        ln(f"{bdr}{pad}{side_l}{row}{side_r}{pad}{bdr}")

    # Signal rings row
    sig = f"{BGN}{'·  ' * 13}·{R}"
    ln(f"{bdr}  {sig:<76}{R}{bdr}")
    ln(f"{bdr}{'':^80}{bdr}")

    # Stats row
    ln(f"{bdr}  {BCY}{'DNS':^12}{R}{GN}│{R}{BCY}{'PORT SCAN':^12}{R}{GN}│{R}{BCY}{'TECH DETECT':^12}{R}{GN}│{R}{BCY}{'INTEL APIS':^12}{R}{GN}│{R}{BCY}{'SHADOW SCORE':^12}{R}  {bdr}")
    ln(f"{bdr}  {GN}{'A/MX/NS/TXT':^12}{R}{GN}│{R}{GN}{'99 ports':^12}{R}{GN}│{R}{GN}{'50+ stacks':^12}{R}{GN}│{R}{GN}{'30+ sources':^12}{R}{GN}│{R}{GN}{'0–100':^12}{R}  {bdr}")
    ln(f"{bdr}  {CY}{'─'*76}{R}{bdr}")

    # Install
    ln(f"{bdr}  {BGN}$ pip install phantomsignal{R}{'':50}{bdr}")
    ln(f"{bdr}  {DM}phantomsignal.sh  ·  github.com/getphantomsignal/phantomsignal  ·  v1.3.0{R}  {bdr}")
    ln(f"{bdr}  {DM}\"See everything. Leave no trace.\"{R}{'':44}{bdr}")

    ln(bot)

    # Pad to exactly 24 lines
    while len(lines) < 24:
        lines.append("")

    return "\n".join(lines[:24])


# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    pieces = {
        "phantom_scene.ans":  scene,
        "phantom_ghost.ans":  standalone_ghost,
        "phantom_splash.ans": splash,
    }

    for filename, fn in pieces.items():
        art = fn()
        # Print to terminal
        print(f"\n{'='*80}")
        print(f"  {filename}")
        print(f"{'='*80}")
        print(art)
        # Save file (raw ANSI bytes)
        out = DOCS / filename
        out.write_text(art + "\n", encoding="utf-8")
        print(f"\n{RST}✓  Saved → {out}")
