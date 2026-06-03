#!/usr/bin/env python3
"""
PhantomSignal ASCII Art Pack
Pure block art — no ANSI colour codes, full CP437 charset
Works in any terminal, README, or raw text context.

Character palette:
  █▓▒░  — shade blocks (solid → fade)
  ▀▄▌▐  — half blocks (sub-cell edges)
  ╔╗╚╝║═╠╣  — double-line box drawing
  ╱╲│·─  — line art / signal chars
  ╰╯     — curve connectors (grin)

Generates:
  docs/assets/phantom_ghost.ans   — standalone phantom figure
  docs/assets/phantom_scene.ans   — full 80-col scene
  docs/assets/phantom_splash.ans  — 80x24 CLI splash
"""
from pathlib import Path

DOCS = Path(__file__).parent.parent / "docs" / "assets"
DOCS.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
#  THE PHANTOM — 38 chars wide, 20 rows
#  Hooded void-face · arms out · clawed hands · jagged tendrils
#  Void face = empty space carved into solid █ body — no colour needed
# ─────────────────────────────────────────────────────────────────────────────
PHANTOM = [
    #          0         1         2         3
    #          0123456789012345678901234567890123456789
    r"            ▄▄████████████▄▄            ",
    r"          ▄██████████████████▄          ",
    r"         ████████████████████████         ",
    r"        ████▓▓▓▓▓▓▓▓▓▓▓▓▓▓████        ",
    r"        ████▓                ▓████        ",
    r"        ████▓  ╰──────────╯  ▓████        ",
    r"         ████████████████████████         ",
    r"     ▄▄███████████████████████████▄▄     ",
    r"     ████████████████████████████████     ",
    r"   ▐██╲▓▓████████████████████▓▓╱██▌   ",
    r"  ╱███╲╲ ▓████████████████████ ╱╱███╲  ",
    r" ╱╱╱ ╲╲  ████████████████████  ╱╱ ╲╲╲ ",
    r"          ██████████████████████          ",
    r"          ▓████████████████████▓          ",
    r"          ██████████████████████          ",
    r"         ▐▌▌  ▌██▌  ▌██▌  ▌██▌▐         ",
    r"          ▌▌  ▐▌ ▐▌  ▌ ▐▌  ▌▌           ",
    r"          ▌    ▌   ▌  ▌   ▌  ▌           ",
    r"           ▌    ▌   ▌▌   ▌    ▌          ",
    r"            ▌         ▌         ▌         ",
]

# signal halo chars per row (left side — mirrored for right)
HALO = [
    " · ░",
    "· ░░",
    "  ░░",
    " ─░░",
    " ─░░",
    " ─░░",
    " ─░░",
    "  ░░",
    "  ░░",
    "  ░░",
    "   ░",
    "   ░",
    "    ",
    "    ",
    "    ",
    "    ",
    "    ",
    "    ",
    "    ",
    "    ",
]


# ─────────────────────────────────────────────────────────────────────────────
#  STANDALONE GHOST
# ─────────────────────────────────────────────────────────────────────────────
def standalone_ghost() -> str:
    W = 48   # total content width
    lines = [
        "",
        "  P H A N T O M   S I G N A L",
        "  " + "─" * 28,
        "  OSINT Intelligence Framework",
        "  " + "─" * 28,
        "",
        "  ·  ·  ·  " + "─" * 18 + "  ·  ·  ·",
        "  " + "░" * (W - 2),
    ]
    for i, row in enumerate(PHANTOM):
        h = HALO[i] if i < len(HALO) else "    "
        lines.append(f"  ░{h[::-1]}{row}{h}░")
    lines += [
        "  " + "░" * (W - 2),
        "  ·  ·  ·  " + "─" * 18 + "  ·  ·  ·",
        "",
        '  "See everything. Leave no trace."',
        "  pip install phantomsignal",
        "",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  FULL SCENE  (80 cols)
# ─────────────────────────────────────────────────────────────────────────────
def scene() -> str:
    lines = []

    def ln(s=""): lines.append(s)
    def box(s): ln(f"║  {s:<76}║")

    ln("╔" + "═" * 78 + "╗")
    ln("║" + " " * 78 + "║")

    # Slant-font title
    box("    ____  __  _____    _   ____________  __  ___")
    box("   / __ \\/ / / /   |  / | / /_  __/ __ \\/  |/  /")
    box("  / /_/ / /_/ / /| | /  |/ / / / / / / / /|_/ /")
    box(" / ____/ __  / ___ |/ /|  / / / / /_/ / /  / /")
    box("/_/   /_/ /_/_/  |_/_/ |_/ /_/  \\____/_/  /_/")
    ln("║" + " " * 78 + "║")
    box("   _____ ___________   _____    __")
    box("  / ___//  _/ ____/ | / /   |  / /")
    box("  \\__ \\ / // / __/  |/ / /| | / /")
    box(" ___/ // // /_/ / /|  / ___ |/ /___")
    box("/____/___/\\____/_/ |_/_/  |_/_____/")
    ln("║" + " " * 78 + "║")

    # Signal divider
    ln("║  ·  ·  ─" + "─" * 56 + "─  ·  ·  ║")
    ln("║" + " " * 78 + "║")

    # Phantom + halo, centred in 80 cols
    PAD = 14
    for i, row in enumerate(PHANTOM):
        h = HALO[i] if i < len(HALO) else "    "
        ln(f"║{' '*PAD}{h[::-1]}░{row}░{h}{' '*PAD}║")

    ln("║" + " " * 78 + "║")
    ln("║  ·  ·  ─" + "─" * 56 + "─  ·  ·  ║")
    ln("║" + " " * 78 + "║")

    box(">> OPEN-SOURCE OSINT INTELLIGENCE FRAMEWORK <<")
    box('"See everything. Leave no trace."')
    ln("║" + " " * 78 + "║")
    box("pip install phantomsignal      github.com/getphantomsignal/phantomsignal")
    box("phantomsignal.sh" + " " * 54 + "v1.3.0")
    ln("║" + " " * 78 + "║")
    ln("╚" + "═" * 78 + "╝")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  SPLASH SCREEN  80×24
# ─────────────────────────────────────────────────────────────────────────────
def splash() -> str:
    lines = []

    def ln(s=""): lines.append(s)
    def box(s): ln(f"║  {s:<76}║")

    ln("╔" + "═" * 78 + "╗")
    ln(f"║  {'PHANTOM SIGNAL':^76}║")
    ln(f"║  {'OPEN-SOURCE OSINT INTELLIGENCE FRAMEWORK':^76}║")
    ln("║  " + "─" * 76 + "║")

    # Top 10 rows of phantom, centred
    PAD = 18
    for i, row in enumerate(PHANTOM[:10]):
        h = HALO[i] if i < len(HALO) else "    "
        side = "·" if i % 3 == 0 else " "
        ln(f"║{' '*PAD}{side}░{h[::-1]}{row}{h}░{side}{' '*PAD}║")

    ln(f"║  {'· ' * 18}·{' ':>5}║")
    ln("║" + " " * 78 + "║")
    ln(f"║  {'DNS':^12}│{'PORT SCAN':^12}│{'TECH DETECT':^12}│{'INTEL APIS':^12}│{'SHADOW SCORE':^12}  ║")
    ln(f"║  {'A/MX/NS/TXT':^12}│{'99 ports':^12}│{'50+ stacks':^12}│{'30+ sources':^12}│{'0-100':^12}  ║")
    ln("║  " + "─" * 76 + "║")
    ln("║  $ pip install phantomsignal" + " " * 49 + "║")
    ln("║  phantomsignal.sh  ·  github.com/getphantomsignal/phantomsignal  ·  v1.3.0  ║")
    ln('║  "See everything. Leave no trace."' + " " * 42 + "║")
    ln("╚" + "═" * 78 + "╝")

    while len(lines) < 24:
        lines.append("")
    return "\n".join(lines[:24])


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    pieces = {
        "phantom_ghost.ans":  standalone_ghost,
        "phantom_scene.ans":  scene,
        "phantom_splash.ans": splash,
    }
    for fname, fn in pieces.items():
        art = fn()
        print(f"\n{'─' * 80}\n  {fname}\n{'─' * 80}")
        print(art)
        (DOCS / fname).write_text(art + "\n", encoding="utf-8")
        print(f"✓  saved → {DOCS / fname}")
