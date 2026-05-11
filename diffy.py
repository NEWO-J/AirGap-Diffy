#!/usr/bin/env python3
"""
diffy.py — Synack Red Team screenshot deduplication tool.

All processing is strictly local.  No network calls are ever made.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import imagehash
from PIL import Image, ImageDraw
from tqdm import tqdm


# ── Manifest ──────────────────────────────────────────────────────────────────

def load_manifest(path: Path) -> Dict[str, str]:
    """Load {abs_path: phash_hex} from disk; returns empty dict on any error."""
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            tqdm.write(f"  [WARN] Manifest at {path} is corrupt — starting fresh.")
    return {}


def save_manifest(path: Path, manifest: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


# ── Masking ───────────────────────────────────────────────────────────────────

def parse_mask(raw: str) -> Tuple[int, int, int, int]:
    """
    argparse type helper: parse 'x1,y1,x2,y2' into a 4-tuple of ints.
    Raises ArgumentTypeError on bad input so argparse surfaces a clean error.
    """
    try:
        parts = [int(v.strip()) for v in raw.split(",")]
        if len(parts) != 4:
            raise ValueError
        x1, y1, x2, y2 = parts
        if x1 >= x2 or y1 >= y2:
            raise argparse.ArgumentTypeError(
                f"Mask requires x1 < x2 and y1 < y2 — got: {raw!r}"
            )
        return (x1, y1, x2, y2)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Mask must be 'x1,y1,x2,y2' (integers) — got: {raw!r}"
        )


def apply_masks(img: Image.Image, masks: List[Tuple[int, int, int, int]]) -> Image.Image:
    """Paint masked regions solid black so they are ignored during hashing."""
    if not masks:
        return img
    img = img.copy().convert("RGB")
    draw = ImageDraw.Draw(img)
    for box in masks:
        draw.rectangle(box, fill=(0, 0, 0))
    return img


# ── Hashing ───────────────────────────────────────────────────────────────────

def compute_hash(
    image_path: Path,
    masks: List[Tuple[int, int, int, int]],
    manifest: Dict[str, str],
) -> Tuple[Path, Optional[str]]:
    """
    Return (path, hex_hash).  Returns (path, None) if the image cannot be read.
    Cache hits are returned from the manifest without re-opening the file.
    """
    key = str(image_path.resolve())
    if key in manifest:
        return image_path, manifest[key]

    try:
        with Image.open(image_path) as img:
            img.load()                          # force decode before closing handle
            masked = apply_masks(img, masks)
            h = imagehash.phash(masked)
            return image_path, str(h)
    except Exception as exc:  # noqa: BLE001
        tqdm.write(f"  [WARN] Cannot read {image_path.name}: {exc}")
        return image_path, None


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate(
    results: List[Tuple[Path, str]],
    threshold: int,
) -> Tuple[List[Path], List[Path]]:
    """
    Greedy first-seen deduplication.

    Iterates results in sorted order (deterministic across runs).  The first
    image in each cluster of visually-similar images is kept as 'unique';
    later images within `threshold` Hamming distance of any unique image are
    marked 'redundant'.

    Returns (unique_paths, redundant_paths).
    """
    # Sort by filename for deterministic canonical selection.
    ordered = sorted(results, key=lambda t: t[0].name.lower())

    unique: List[Tuple[Path, imagehash.ImageHash]] = []
    redundant: List[Path] = []

    for path, hex_hash in ordered:
        h = imagehash.hex_to_hash(hex_hash)
        match = next(
            (True for _, existing in unique if (h - existing) <= threshold),
            False,
        )
        if match:
            redundant.append(path)
        else:
            unique.append((path, h))

    return [p for p, _ in unique], redundant


# ── HTML Report ───────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Diffy Triage Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:28px}}
  h1{{color:#58a6ff;font-size:1.5rem;margin-bottom:6px}}
  .meta{{color:#8b949e;font-size:0.8rem;margin-bottom:28px;line-height:1.7}}
  .meta span{{margin-right:18px}}
  .stats{{display:flex;gap:16px;margin-bottom:36px;flex-wrap:wrap}}
  .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;
         padding:16px 22px;min-width:148px}}
  .stat-label{{color:#8b949e;font-size:0.72rem;text-transform:uppercase;letter-spacing:.06em}}
  .stat-value{{color:#f0f6fc;font-size:1.9rem;font-weight:700;margin-top:4px}}
  .stat-value.accent{{color:#3fb950}}
  .section-title{{color:#58a6ff;font-size:1rem;margin-bottom:16px;
                  padding-bottom:8px;border-bottom:1px solid #21262d}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
         overflow:hidden;transition:border-color .15s,transform .15s}}
  .card:hover{{border-color:#58a6ff;transform:translateY(-2px)}}
  .card img{{width:100%;display:block;object-fit:cover;height:190px;
             background:#0d1117}}
  .card-body{{padding:10px 13px 12px}}
  .card-name{{color:#e6edf3;font-size:0.78rem;white-space:nowrap;
              overflow:hidden;text-overflow:ellipsis}}
  .card-hash{{color:#8b949e;font-size:0.68rem;margin-top:5px;letter-spacing:.03em}}
  .badge{{display:inline-block;background:#1f6feb;color:#fff;
          font-size:0.65rem;padding:1px 6px;border-radius:3px;
          margin-left:6px;vertical-align:middle}}
</style>
</head>
<body>
<h1>Diffy &mdash; Triage Report</h1>
<p class="meta">
  <span>Generated: {timestamp}</span>
  <span>Directory: {directory}</span>
  <span>Threshold: {threshold} bits</span>
  <span>Workers: {workers}</span>
  {masks_meta}
</p>
<div class="stats">
  <div class="stat">
    <div class="stat-label">Total processed</div>
    <div class="stat-value">{total}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Unique</div>
    <div class="stat-value accent">{unique}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Redundant</div>
    <div class="stat-value">{redundant}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Triage saved</div>
    <div class="stat-value accent">{pct_saved}%</div>
  </div>
</div>
<p class="section-title">Unique Screenshots &mdash; {unique} images</p>
<div class="grid">
{cards}
</div>
</body>
</html>
"""

_CARD_TEMPLATE = (
    '  <div class="card">\n'
    '    <img src="data:image/{fmt};base64,{b64}" alt="{name}" loading="lazy">\n'
    '    <div class="card-body">\n'
    '      <div class="card-name" title="{name}">{name}</div>\n'
    '      <div class="card-hash">pHash: {phash}</div>\n'
    '    </div>\n'
    '  </div>'
)


def _embed_image(path: Path) -> Tuple[str, str]:
    """Return (base64_data, mime_subtype) for an image file."""
    suffix = path.suffix.lower().lstrip(".")
    fmt = "jpeg" if suffix in ("jpg", "jpeg") else "png"
    return base64.b64encode(path.read_bytes()).decode(), fmt


def build_report(
    unique_paths: List[Path],
    hash_lookup: Dict[str, str],
    output_path: Path,
    threshold: int,
    workers: int,
    masks: List[Tuple[int, int, int, int]],
    directory: Path,
    total: int,
    redundant_count: int,
) -> None:
    pct_saved = round(redundant_count / total * 100) if total else 0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    masks_meta = ""
    if masks:
        boxes = "; ".join(str(m) for m in masks)
        masks_meta = f'<span>Masks: {boxes}</span>'

    cards_html: List[str] = []
    for p in unique_paths:
        b64, fmt = _embed_image(p)
        phash = hash_lookup.get(str(p.resolve()), "n/a")
        cards_html.append(
            _CARD_TEMPLATE.format(fmt=fmt, b64=b64, name=p.name, phash=phash)
        )

    html = _HTML_TEMPLATE.format(
        timestamp=timestamp,
        directory=str(directory.resolve()),
        threshold=threshold,
        workers=workers,
        masks_meta=masks_meta,
        total=total,
        unique=len(unique_paths),
        redundant=redundant_count,
        pct_saved=pct_saved,
        cards="\n".join(cards_html),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="diffy",
        description=(
            "Visual screenshot deduplication for Synack Red Team triage.\n"
            "All processing is local — no network access required."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python diffy.py ./screenshots
  python diffy.py ./shots --threshold 8 --workers 8
  python diffy.py ./shots --mask 0,0,1920,60 --mask 0,980,1920,1080
  python diffy.py ./shots --manifest ~/.diffy/hashes.json --output report.html
""",
    )
    p.add_argument(
        "directory",
        type=Path,
        help="Directory containing screenshot files",
    )
    p.add_argument(
        "--threshold", "-t",
        type=int,
        default=5,
        metavar="BITS",
        help="Hamming distance threshold for duplicate detection (default: 5)",
    )
    p.add_argument(
        "--workers", "-w",
        type=int,
        default=4,
        metavar="N",
        help="Number of parallel hashing threads (default: 4)",
    )
    p.add_argument(
        "--mask", "-m",
        dest="masks",
        type=parse_mask,
        action="append",
        default=[],
        metavar="x1,y1,x2,y2",
        help=(
            "Pixel region to black-out before hashing, e.g. a rotating banner "
            "or clock. May be specified multiple times."
        ),
    )
    p.add_argument(
        "--manifest",
        type=Path,
        default=Path("diffy_manifest.json"),
        metavar="PATH",
        help="JSON file for caching hashes across runs (default: diffy_manifest.json)",
    )
    p.add_argument(
        "--no-manifest",
        action="store_true",
        help="Disable manifest caching; rehash everything from scratch",
    )
    p.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("triage_report.html"),
        metavar="PATH",
        help="Output HTML report path (default: triage_report.html)",
    )
    p.add_argument(
        "--extensions",
        nargs="+",
        default=["png", "jpg", "jpeg"],
        metavar="EXT",
        help="File extensions to include (default: png jpg jpeg)",
    )
    return p


def collect_images(directory: Path, extensions: List[str]) -> List[Path]:
    """Collect all image files with the given extensions from directory."""
    seen = set()
    images = []
    for ext in extensions:
        for path in directory.glob(f"*.{ext}"):
            if path not in seen:
                seen.add(path)
                images.append(path)
        for path in directory.glob(f"*.{ext.upper()}"):
            if path not in seen:
                seen.add(path)
                images.append(path)
    return sorted(images, key=lambda p: p.name.lower())


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    directory: Path = args.directory
    if not directory.is_dir():
        parser.error(f"Not a directory: {directory}")

    images = collect_images(directory, args.extensions)
    if not images:
        print(f"[!] No images found in {directory}")
        sys.exit(0)

    manifest: Dict[str, str] = {} if args.no_manifest else load_manifest(args.manifest)
    cached_count = sum(1 for p in images if str(p.resolve()) in manifest)

    # ── Banner ────────────────────────────────────────────────────────────────
    print()
    print("  Diffy — Synack Red Team Triage")
    print(f"  {'─' * 44}")
    print(f"  Directory  : {directory.resolve()}")
    print(f"  Images     : {len(images)}")
    print(f"  Cached     : {cached_count}  (manifest hits, will skip re-hash)")
    print(f"  Threshold  : {args.threshold} bits Hamming distance")
    print(f"  Workers    : {args.workers}")
    if args.masks:
        for i, m in enumerate(args.masks, 1):
            print(f"  Mask #{i}    : {m}")
    print(f"  Manifest   : {'disabled' if args.no_manifest else args.manifest}")
    print(f"  Report     : {args.output}")
    print()

    t_start = time.perf_counter()

    # ── Phase 1: hash ─────────────────────────────────────────────────────────
    hashed: List[Tuple[Path, str]] = []
    failed: List[Path] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(compute_hash, img, args.masks, manifest): img
            for img in images
        }
        with tqdm(
            total=len(images),
            desc="  Hashing  ",
            unit="img",
            ncols=68,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]",
        ) as bar:
            for future in as_completed(futures):
                path, hex_hash = future.result()
                if hex_hash is not None:
                    hashed.append((path, hex_hash))
                    manifest[str(path.resolve())] = hex_hash
                else:
                    failed.append(path)
                bar.update(1)

    if not args.no_manifest:
        save_manifest(args.manifest, manifest)

    if not hashed:
        print("[!] No images could be hashed — check file permissions / format.")
        sys.exit(1)

    # ── Phase 2: deduplicate ──────────────────────────────────────────────────
    with tqdm(
        total=len(hashed),
        desc="  Deduping  ",
        unit="img",
        ncols=68,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]",
    ) as bar:
        unique_paths, redundant_paths = deduplicate(hashed, args.threshold)
        bar.update(len(hashed))

    # ── Phase 3: report ───────────────────────────────────────────────────────
    print()
    with tqdm(
        total=len(unique_paths),
        desc="  Reporting ",
        unit="img",
        ncols=68,
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]",
    ) as bar:
        build_report(
            unique_paths=unique_paths,
            hash_lookup=manifest,
            output_path=args.output,
            threshold=args.threshold,
            workers=args.workers,
            masks=args.masks,
            directory=directory,
            total=len(hashed),
            redundant_count=len(redundant_paths),
        )
        bar.update(len(unique_paths))

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = time.perf_counter() - t_start
    pct_saved = round(len(redundant_paths) / len(hashed) * 100) if hashed else 0

    print()
    print(f"  {'─' * 44}")
    print(f"  Total processed  : {len(hashed)}")
    print(f"  Unique           : {len(unique_paths)}")
    print(f"  Redundant        : {len(redundant_paths)}")
    if failed:
        print(f"  Failed (skipped) : {len(failed)}")
    print(f"  Triage saved     : {pct_saved}%")
    print(f"  Elapsed          : {elapsed:.2f}s")
    print(f"  {'─' * 44}")
    print(f"  Report    -> {args.output}")
    if not args.no_manifest:
        print(f"  Manifest  -> {args.manifest}")
    print()


if __name__ == "__main__":
    main()
