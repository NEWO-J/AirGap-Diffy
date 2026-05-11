#!/usr/bin/env python3
"""
demo/gen_screenshots.py — Generate sample screenshots for testing diffy scan.

Produces 22 images across 5 page types:
  - 4 near-duplicate variants per page type (timestamp changes in browser chrome)
  - 2 genuinely unique error pages
Expected scan result: ~5 unique, ~17 filtered (~77% reduction).

The rotating timestamp sits at pixel region (1100, 36, 1280, 80) of the browser
chrome. Use --mask 1100,36,1280,80 to suppress false positives from it.
"""
from __future__ import annotations

import platform
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict

from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = Path(__file__).parent / "screenshots"
W, H = 1280, 800

# ── Font loader ───────────────────────────────────────────────────────────────

_FONT_CACHE: Dict[int, ImageFont.FreeTypeFont] = {}


def _load_font(size: int) -> ImageFont.FreeTypeFont:
    candidates = []
    if platform.system() == "Windows":
        candidates += [r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\segoeui.ttf"]
    elif platform.system() == "Darwin":
        candidates += ["/System/Library/Fonts/Helvetica.ttc", "/Library/Fonts/Arial.ttf"]
    else:
        candidates += [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ]
    candidates += ["arial.ttf", "Arial.ttf"]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def font(size: int) -> ImageFont.FreeTypeFont:
    if size not in _FONT_CACHE:
        _FONT_CACHE[size] = _load_font(size)
    return _FONT_CACHE[size]


# ── Browser chrome ────────────────────────────────────────────────────────────

def draw_chrome(draw: ImageDraw.ImageDraw, url: str, timestamp: str) -> None:
    """
    Simulate a minimal browser chrome with address bar.
    The timestamp in the top-right is what changes between variants —
    use --mask 1100,36,1280,80 to suppress it during hashing.
    """
    draw.rectangle([0, 0, W, 36], fill="#2d2d2d")
    draw.rectangle([0, 0, 210, 36], fill="#3c3c3c", outline="#555")
    draw.text((12, 9), "target.local", fill="#cccccc", font=font(13))
    draw.text((230, 9), "×", fill="#888", font=font(13))

    draw.rectangle([0, 36, W, 80], fill="#1e1e1e")
    draw.rectangle([58, 44, W - 130, 72], fill="#2a2a2a", outline="#3d3d3d")
    draw.text((68, 51), f"🔒  {url}", fill="#aaa", font=font(12))
    # Rotating element — good demo of --mask
    draw.text((W - 175, 51), f"🕐 {timestamp}", fill="#777", font=font(12))


# ── Page renderers ────────────────────────────────────────────────────────────

_BANNERS = [
    "🎉  Special offer — upgrade today!",
    "🔔  New features available in v4.2",
    "⚠️   Maintenance window Sunday 02:00 UTC",
    "📢  Security advisory — update your password",
]


def page_login(draw: ImageDraw.ImageDraw, variant: int) -> None:
    draw.rectangle([0, 80, W, H], fill="#f0f2f5")
    # Card
    draw.rectangle([430, 160, 850, 600], fill="white", outline="#dde1e7")
    draw.text((570, 205), "Sign In", fill="#1a1a2e", font=font(30))
    for i, (label, y) in enumerate([("Email", 295), ("Password", 370)]):
        draw.text((490, y), label, fill="#555", font=font(13))
        draw.rectangle([490, y + 22, 810, y + 52], fill="#f9f9f9", outline="#ccc")
    draw.rectangle([490, 455, 810, 493], fill="#4361ee")
    draw.text((605, 463), "Log In", fill="white", font=font(17))
    draw.text((530, 515), "Forgot password?", fill="#4361ee", font=font(13))
    # Rotating banner at bottom — will cause false duplicates without masking
    draw.rectangle([0, 556, W, 596], fill="#4361ee")
    draw.text((20, 566), _BANNERS[variant % len(_BANNERS)], fill="white", font=font(13))


def page_dashboard(draw: ImageDraw.ImageDraw, variant: int) -> None:
    draw.rectangle([0, 80, W, H], fill="#f4f6f9")
    # Sidebar
    draw.rectangle([0, 80, 230, H], fill="#1a1a2e")
    for i, item in enumerate(["Dashboard", "Users", "Orders", "Reports", "Settings"]):
        y = 105 + i * 32
        if i == 0:
            draw.rectangle([0, y - 4, 230, y + 24], fill="#4361ee")
        draw.text((20, y), item, fill="white" if i == 0 else "#aaa", font=font(14))
    # Main area
    counts = [(1247 + variant, "Users", "#4361ee"), (382 + variant * 3, "Orders", "#7209b7"), (94 + variant, "Alerts", "#e63946")]
    for i, (n, label, color) in enumerate(counts):
        x = 255 + i * 310
        draw.rectangle([x, 110, x + 280, 200], fill="white", outline="#e0e0e0")
        draw.text((x + 18, 125), str(n), fill=color, font=font(30))
        draw.text((x + 18, 165), label, fill="#666", font=font(13))
    draw.text((255, 220), "Recent Activity", fill="#1a1a2e", font=font(18))
    draw.line([255, 245, W - 20, 245], fill="#e0e0e0", width=1)
    for row in range(5):
        y = 260 + row * 48
        draw.rectangle([255, y, W - 20, y + 40], fill="#fff" if row % 2 == 0 else "#f9f9f9", outline="#eee")
        draw.text((270, y + 12), f"Event #{1000 + row + variant}", fill="#333", font=font(13))
        draw.text((W - 140, y + 12), "2026-05-11", fill="#888", font=font(12))


def page_profile(draw: ImageDraw.ImageDraw, variant: int) -> None:
    draw.rectangle([0, 80, W, H], fill="#f4f6f9")
    draw.rectangle([60, 110, W - 60, 690], fill="white", outline="#e0e0e0")
    colors = ["#4361ee", "#7209b7", "#e63946", "#2ec4b6"]
    draw.ellipse([140, 145, 270, 275], fill=colors[variant % len(colors)])
    initials = ["AU", "BU", "CJ", "DJ"]
    draw.text((162, 184), initials[variant % len(initials)], fill="white", font=font(44))
    names = ["Alice User", "Bob Smith", "Carol Jones", "Dave Kim"]
    draw.text((305, 168), names[variant % len(names)], fill="#1a1a2e", font=font(24))
    draw.text((305, 204), f"user{variant + 1}@target.local", fill="#666", font=font(14))
    draw.text((100, 305), "Account Details", fill="#1a1a2e", font=font(17))
    draw.line([100, 330, W - 100, 330], fill="#eee", width=1)
    fields = [("User ID", str(1000 + variant)), ("Role", "user"), ("Created", "2024-01-15"), ("MFA", "Enabled"), ("Last login", "2026-05-11")]
    for i, (k, v) in enumerate(fields):
        y = 348 + i * 52
        draw.rectangle([100, y, W - 100, y + 44], fill="#f9f9f9" if i % 2 == 0 else "white")
        draw.text((115, y + 13), k, fill="#888", font=font(13))
        draw.text((320, y + 13), v, fill="#333", font=font(13))


def page_error403(draw: ImageDraw.ImageDraw, variant: int) -> None:
    draw.rectangle([0, 80, W, H], fill="#fff5f5")
    draw.text((470, 210), "403", fill="#e53e3e", font=font(100))
    draw.text((455, 330), "Forbidden", fill="#c53030", font=font(28))
    messages = [
        "You don't have permission to access this resource.",
        "Access denied. Contact your system administrator.",
        "Insufficient privileges for this operation.",
        "This resource requires elevated permissions.",
    ]
    draw.text((310, 392), messages[variant % len(messages)], fill="#666", font=font(14))
    draw.rectangle([490, 455, 790, 495], fill="#e53e3e")
    draw.text((570, 464), "← Go Back", fill="white", font=font(16))
    draw.text((490, 518), f"Request ID: req_{0xDEAD + variant:04x}", fill="#aaa", font=font(12))


def page_admin(draw: ImageDraw.ImageDraw, variant: int) -> None:
    draw.rectangle([0, 80, W, H], fill="#0f0f23")
    draw.rectangle([0, 80, 240, H], fill="#16213e")
    draw.text((20, 102), "ADMIN PANEL", fill="#e94560", font=font(14))
    draw.line([0, 124, 240, 124], fill="#e94560", width=1)
    for i, item in enumerate(["Users", "Sessions", "Audit Log", "Config", "Logout"]):
        draw.text((20, 136 + i * 30), item, fill="#ccc" if i > 0 else "white", font=font(13))
    draw.rectangle([240, 80, W, H], fill="#0f0f23")
    draw.text((260, 100), "User Management", fill="#e94560", font=font(20))
    draw.rectangle([260, 132, W - 20, 158], fill="#16213e")
    for i, hdr in enumerate(["ID", "Name", "Email", "Role", "Status"]):
        draw.text((270 + i * 196, 140), hdr, fill="#888", font=font(12))
    rows = [
        ("0", "Admin", "admin@target.local", "admin", "Active"),
        ("1", "Alice", "alice@target.local", "user",  "Active"),
        ("2", "Bob",   "bob@target.local",   "user",  f"Sessions: {3 + variant}"),
    ]
    for r, row in enumerate(rows):
        y = 164 + r * 44
        draw.rectangle([260, y, W - 20, y + 38], fill="#16213e" if r % 2 else "#0f0f23")
        for c, cell in enumerate(row):
            color = "#e94560" if c == 3 and cell == "admin" else "#ccc"
            draw.text((270 + c * 196, y + 12), cell, fill=color, font=font(12))


# ── One-off unique pages ──────────────────────────────────────────────────────

def page_404(draw: ImageDraw.ImageDraw) -> None:
    draw.rectangle([0, 80, W, H], fill="#fff9e6")
    draw.text((475, 215), "404", fill="#d69e2e", font=font(100))
    draw.text((455, 335), "Not Found", fill="#b7791f", font=font(28))
    draw.text((370, 395), "The page you're looking for doesn't exist.", fill="#666", font=font(14))
    draw.rectangle([490, 455, 790, 495], fill="#d69e2e")
    draw.text((555, 464), "← Home", fill="white", font=font(16))


def page_500(draw: ImageDraw.ImageDraw) -> None:
    draw.rectangle([0, 80, W, H], fill="#f7f7f7")
    draw.text((455, 215), "500", fill="#444", font=font(100))
    draw.text((420, 335), "Internal Server Error", fill="#333", font=font(24))
    draw.text((310, 392), "Something went wrong on our end. Please try again later.", fill="#666", font=font(14))
    draw.rectangle([490, 455, 790, 495], fill="#555")
    draw.text((540, 464), "Refresh Page", fill="white", font=font(16))


# ── Generator ─────────────────────────────────────────────────────────────────

PAGE_DEFS = [
    ("login",     "https://target.local/login",        page_login),
    ("dashboard", "https://target.local/dashboard",    page_dashboard),
    ("profile",   "https://target.local/profile",      page_profile),
    ("error403",  "https://target.local/error/403",    page_error403),
    ("admin",     "https://target.local/admin/users",  page_admin),
]


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\n  Generating demo screenshots → {OUTPUT_DIR}\n")

    base_ts = datetime(2026, 5, 11, 14, 0, 0)
    count = 0

    for name, url, fn in PAGE_DEFS:
        for v in range(4):
            ts = base_ts + timedelta(minutes=len(PAGE_DEFS) * v * 4 + PAGE_DEFS.index((name, url, fn)) * 7)
            img = Image.new("RGB", (W, H), "#ffffff")
            draw = ImageDraw.Draw(img)
            draw_chrome(draw, url, ts.strftime("%H:%M:%S"))
            fn(draw, v)
            path = OUTPUT_DIR / f"{name}_v{v}.png"
            img.save(path)
            count += 1
            print(f"  {path.name}")

    # Genuinely unique one-off pages
    for label, url_path, fn in [("error404", "/error/404", page_404), ("error500", "/error/500", page_500)]:
        img = Image.new("RGB", (W, H), "#ffffff")
        draw = ImageDraw.Draw(img)
        draw_chrome(draw, f"https://target.local{url_path}", "14:59:01")
        fn(draw)
        path = OUTPUT_DIR / f"{label}.png"
        img.save(path)
        count += 1
        print(f"  {path.name}")

    unique_count = len(PAGE_DEFS) + 2
    redundant_count = count - unique_count
    print(f"\n  {count} screenshots written")
    print(f"  Expected → ~{unique_count} unique, ~{redundant_count} filtered ({redundant_count * 100 // count}% reduction)")
    print(f"\n  Run:  python diffy.py scan demo/screenshots/ --output demo/scan_report.html")
    print(f"  Mask: python diffy.py scan demo/screenshots/ --mask 1100,36,1280,80 --output demo/scan_report_masked.html\n")


if __name__ == "__main__":
    main()
