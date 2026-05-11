#!/usr/bin/env python3
"""
diffy.py — Synack Red Team triage tool.

  scan   Visual screenshot deduplication (pHash)
  diff   Differential HTTP access-control testing (IDOR / BOLA detection)
"""
from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import http.server
import json
import socketserver
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import imagehash
import requests
import urllib3
from PIL import Image, ImageDraw
from requests.adapters import HTTPAdapter
from tqdm import tqdm
from urllib3.util.retry import Retry


# ── Shared: manifest ──────────────────────────────────────────────────────────

def load_manifest(path: Path) -> Dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            tqdm.write(f"  [WARN] Manifest corrupt — starting fresh.")
    return {}


def save_manifest(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN — screenshot deduplication
# ══════════════════════════════════════════════════════════════════════════════

def parse_mask(raw: str) -> Tuple[int, int, int, int]:
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
    if not masks:
        return img
    img = img.copy().convert("RGB")
    draw = ImageDraw.Draw(img)
    for box in masks:
        draw.rectangle(box, fill=(0, 0, 0))
    return img


def compute_hash(
    image_path: Path,
    masks: List[Tuple[int, int, int, int]],
    manifest: Dict[str, Any],
) -> Tuple[Path, Optional[str]]:
    key = str(image_path.resolve())
    if key in manifest:
        return image_path, manifest[key]
    try:
        with Image.open(image_path) as img:
            img.load()
            masked = apply_masks(img, masks)
            return image_path, str(imagehash.phash(masked))
    except Exception as exc:
        tqdm.write(f"  [WARN] Cannot read {image_path.name}: {exc}")
        return image_path, None


def deduplicate(
    results: List[Tuple[Path, str]],
    threshold: int,
) -> Tuple[List[Path], List[Path]]:
    ordered = sorted(results, key=lambda t: t[0].name.lower())
    unique: List[Tuple[Path, imagehash.ImageHash]] = []
    redundant: List[Path] = []
    for path, hex_hash in ordered:
        h = imagehash.hex_to_hash(hex_hash)
        if any((h - ex) <= threshold for _, ex in unique):
            redundant.append(path)
        else:
            unique.append((path, h))
    return [p for p, _ in unique], redundant


def _embed_image(path: Path) -> Tuple[str, str]:
    suffix = path.suffix.lower().lstrip(".")
    fmt = "jpeg" if suffix in ("jpg", "jpeg") else "png"
    return base64.b64encode(path.read_bytes()).decode(), fmt


def collect_images(directory: Path, extensions: List[str]) -> List[Path]:
    seen: set = set()
    images: List[Path] = []
    for ext in extensions:
        for path in [*directory.glob(f"*.{ext}"), *directory.glob(f"*.{ext.upper()}")]:
            if path not in seen:
                seen.add(path)
                images.append(path)
    return sorted(images, key=lambda p: p.name.lower())


# ── Scan HTML report ──────────────────────────────────────────────────────────

_SCAN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Diffy — Scan Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:28px}}
  h1{{color:#58a6ff;font-size:1.5rem;margin-bottom:6px}}
  .meta{{color:#8b949e;font-size:.8rem;margin-bottom:28px;line-height:1.7}}
  .meta span{{margin-right:18px}}
  .stats{{display:flex;gap:16px;margin-bottom:36px;flex-wrap:wrap}}
  .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 22px;min-width:148px}}
  .stat-label{{color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}}
  .stat-value{{color:#f0f6fc;font-size:1.9rem;font-weight:700;margin-top:4px}}
  .stat-value.g{{color:#3fb950}}
  .section-title{{color:#58a6ff;font-size:1rem;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #21262d}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;transition:border-color .15s,transform .15s}}
  .card:hover{{border-color:#58a6ff;transform:translateY(-2px)}}
  .card img{{width:100%;display:block;object-fit:cover;height:190px;background:#0d1117}}
  .card-body{{padding:10px 13px 12px}}
  .card-name{{color:#e6edf3;font-size:.78rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .card-hash{{color:#8b949e;font-size:.68rem;margin-top:5px;letter-spacing:.03em}}
</style>
</head>
<body>
<h1>Diffy &mdash; Scan Report</h1>
<p class="meta">
  <span>Generated: {timestamp}</span>
  <span>Directory: {directory}</span>
  <span>Threshold: {threshold} bits</span>
  {masks_meta}
</p>
<div class="stats">
  <div class="stat"><div class="stat-label">Total</div><div class="stat-value">{total}</div></div>
  <div class="stat"><div class="stat-label">Unique</div><div class="stat-value g">{unique}</div></div>
  <div class="stat"><div class="stat-label">Redundant</div><div class="stat-value">{redundant}</div></div>
  <div class="stat"><div class="stat-label">Saved</div><div class="stat-value g">{pct_saved}%</div></div>
</div>
<p class="section-title">Unique Screenshots &mdash; {unique} images</p>
<div class="grid">
{cards}
</div>
</body>
</html>
"""

_SCAN_CARD = (
    '  <div class="card">\n'
    '    <img src="data:image/{fmt};base64,{b64}" alt="{name}" loading="lazy">\n'
    '    <div class="card-body">\n'
    '      <div class="card-name" title="{name}">{name}</div>\n'
    '      <div class="card-hash">pHash: {phash}</div>\n'
    '    </div>\n'
    '  </div>'
)


def build_scan_report(
    unique_paths: List[Path],
    hash_lookup: Dict[str, Any],
    output_path: Path,
    threshold: int,
    masks: List[Tuple[int, int, int, int]],
    directory: Path,
    total: int,
    redundant_count: int,
) -> None:
    pct_saved = round(redundant_count / total * 100) if total else 0
    masks_meta = (
        f'<span>Masks: {"; ".join(str(m) for m in masks)}</span>' if masks else ""
    )
    cards = []
    for p in unique_paths:
        b64, fmt = _embed_image(p)
        phash = hash_lookup.get(str(p.resolve()), "n/a")
        cards.append(_SCAN_CARD.format(fmt=fmt, b64=b64, name=p.name, phash=phash))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        _SCAN_HTML.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            directory=str(directory.resolve()),
            threshold=threshold,
            masks_meta=masks_meta,
            total=total,
            unique=len(unique_paths),
            redundant=redundant_count,
            pct_saved=pct_saved,
            cards="\n".join(cards),
        ),
        encoding="utf-8",
    )


# ── Scan command ──────────────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> None:
    directory: Path = args.directory
    if not directory.is_dir():
        print(f"[!] Not a directory: {directory}", file=sys.stderr)
        sys.exit(1)

    images = collect_images(directory, args.extensions)
    if not images:
        print(f"[!] No images found in {directory}")
        sys.exit(0)

    manifest: Dict[str, Any] = {} if args.no_manifest else load_manifest(args.manifest)
    cached = sum(1 for p in images if str(p.resolve()) in manifest)

    print(f"\n  Diffy scan — {directory.resolve()}")
    print(f"  {'─'*44}")
    print(f"  Images    : {len(images)}  ({cached} cached)")
    print(f"  Threshold : {args.threshold} bits")
    print(f"  Workers   : {args.workers}")
    for i, m in enumerate(args.masks, 1):
        print(f"  Mask #{i}   : {m}")
    print()

    t0 = time.perf_counter()
    hashed: List[Tuple[Path, str]] = []
    failed: List[Path] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(compute_hash, img, args.masks, manifest): img for img in images}
        with tqdm(total=len(images), desc="  Hashing  ", unit="img", ncols=68,
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]") as bar:
            for fut in as_completed(futures):
                path, h = fut.result()
                if h is not None:
                    hashed.append((path, h))
                    manifest[str(path.resolve())] = h
                else:
                    failed.append(path)
                bar.update(1)

    if not args.no_manifest:
        save_manifest(args.manifest, manifest)
    if not hashed:
        print("[!] No images could be hashed.")
        sys.exit(1)

    unique_paths, redundant_paths = deduplicate(hashed, args.threshold)

    print()
    print("[*] Building scan report…")
    build_scan_report(
        unique_paths=unique_paths,
        hash_lookup=manifest,
        output_path=args.output,
        threshold=args.threshold,
        masks=args.masks,
        directory=directory,
        total=len(hashed),
        redundant_count=len(redundant_paths),
    )

    elapsed = time.perf_counter() - t0
    pct = round(len(redundant_paths) / len(hashed) * 100) if hashed else 0
    print(f"\n  {'─'*44}")
    print(f"  Total     : {len(hashed)}")
    print(f"  Unique    : {len(unique_paths)}")
    print(f"  Redundant : {len(redundant_paths)}")
    if failed:
        print(f"  Failed    : {len(failed)}")
    print(f"  Saved     : {pct}%")
    print(f"  Elapsed   : {elapsed:.2f}s")
    print(f"  Report -> {args.output}")
    if not args.no_manifest:
        print(f"  Cache  -> {args.manifest}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  DIFF — HTTP differential access-control testing
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthState:
    label: str
    headers: Dict[str, str]


@dataclass
class HttpResponse:
    status: int
    content_type: str
    body: str
    size: int
    elapsed_ms: int
    is_json: bool
    json_data: Any = None
    error: str = ""


@dataclass
class Finding:
    url: str
    baseline: str
    test: str
    severity: str               # CRITICAL | HIGH | MEDIUM | INFO
    reason: str
    baseline_resp: HttpResponse
    test_resp: HttpResponse
    similarity: float
    diff_lines: List[str] = field(default_factory=list)
    json_diffs: List[str] = field(default_factory=list)


# ── Session parsing ───────────────────────────────────────────────────────────

def parse_auth_arg(raw: str) -> Tuple[str, str, str]:
    """
    Parse 'label:HeaderName:HeaderValue'.
    Splits on the first two colons only, so values containing colons are safe.
    'anon::' or 'anon:' yields an empty-header session.
    """
    parts = raw.split(":", 2)
    label = parts[0].strip()
    if not label:
        raise argparse.ArgumentTypeError(f"Session label cannot be empty: {raw!r}")
    header_name = parts[1].strip() if len(parts) > 1 else ""
    header_value = parts[2].strip() if len(parts) > 2 else ""
    return label, header_name, header_value


def build_auth_states(
    auth_args: List[Tuple[str, str, str]],
    sessions_file: Optional[Path],
) -> List[AuthState]:
    state_map: Dict[str, Dict[str, str]] = {}

    for label, hname, hval in (auth_args or []):
        state_map.setdefault(label, {})
        if hname:
            state_map[label][hname] = hval

    if sessions_file:
        if not sessions_file.is_file():
            print(f"[!] Sessions file not found: {sessions_file}", file=sys.stderr)
            sys.exit(1)
        try:
            data = json.loads(sessions_file.read_text(encoding="utf-8"))
            for label, headers in data.items():
                state_map[label] = dict(headers)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[!] Cannot read sessions file: {exc}", file=sys.stderr)
            sys.exit(1)

    if not state_map:
        print("[!] No auth sessions defined. Use --auth or --sessions-file.", file=sys.stderr)
        sys.exit(1)

    return [AuthState(label=k, headers=v) for k, v in state_map.items()]


# ── HTTP fetching ─────────────────────────────────────────────────────────────

_host_locks: Dict[str, threading.Lock] = {}
_host_lock_guard = threading.Lock()


def _host_lock(url: str) -> threading.Lock:
    host = urllib.parse.urlparse(url).netloc
    with _host_lock_guard:
        if host not in _host_locks:
            _host_locks[host] = threading.Lock()
        return _host_locks[host]


def _make_http_session(verify_ssl: bool) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 502, 503])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.verify = verify_ssl
    return s


def _fetch(sess: requests.Session, url: str, headers: Dict[str, str], timeout: int) -> HttpResponse:
    try:
        r = sess.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        body = r.text
        ct = r.headers.get("Content-Type", "")
        is_json = False
        json_data = None
        if "json" in ct:
            try:
                json_data = r.json()
                is_json = True
            except ValueError:
                pass
        return HttpResponse(
            status=r.status_code,
            content_type=ct,
            body=body,
            size=len(r.content),
            elapsed_ms=int(r.elapsed.total_seconds() * 1000),
            is_json=is_json,
            json_data=json_data,
        )
    except requests.exceptions.SSLError as exc:
        return HttpResponse(0, "", "", 0, 0, False, error=f"SSL error: {exc}")
    except requests.exceptions.ConnectionError as exc:
        return HttpResponse(0, "", "", 0, 0, False, error=f"Connection error: {exc}")
    except requests.exceptions.Timeout:
        return HttpResponse(0, "", "", 0, 0, False, error="Timeout")
    except Exception as exc:
        return HttpResponse(0, "", "", 0, 0, False, error=str(exc))


# ── Diffing and severity ──────────────────────────────────────────────────────

def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Cap at 8 KB each to keep SequenceMatcher fast on large responses.
    return difflib.SequenceMatcher(None, a[:8192], b[:8192]).ratio()


def _json_diff(a: Any, b: Any, path: str = "root") -> List[str]:
    out: List[str] = []
    if type(a) is not type(b):
        out.append(f"{path}: type {type(a).__name__} → {type(b).__name__}")
        return out
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a:
                out.append(f"{path}.{key}: [KEY ADDED IN TEST]")
            elif key not in b:
                out.append(f"{path}.{key}: [KEY REMOVED IN TEST]")
            else:
                out.extend(_json_diff(a[key], b[key], f"{path}.{key}"))
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append(f"{path}: list length {len(a)} → {len(b)}")
        for i, (x, y) in enumerate(zip(a[:20], b[:20])):
            out.extend(_json_diff(x, y, f"{path}[{i}]"))
    else:
        if a != b:
            out.append(f"{path}: {str(a)[:80]!r} → {str(b)[:80]!r}")
    return out


def _text_diff(a: str, b: str, la: str, lb: str) -> List[str]:
    return list(difflib.unified_diff(
        a[:6000].splitlines(keepends=True),
        b[:6000].splitlines(keepends=True),
        fromfile=la, tofile=lb, n=2,
    ))


def _severity(baseline: HttpResponse, test: HttpResponse, sim: float) -> Tuple[str, str]:
    if baseline.error or test.error:
        err = baseline.error or test.error
        return "INFO", f"Request failed: {err}"

    b_ok = 200 <= baseline.status < 300
    t_ok = 200 <= test.status < 300

    if b_ok and t_ok:
        if sim >= 0.85:
            return "CRITICAL", f"Test session mirrors authorized response ({sim:.0%} body similarity)"
        if sim >= 0.55:
            return "HIGH", f"Test session receives substantial authorized data ({sim:.0%} body similarity)"
        return "MEDIUM", f"Test session receives 2xx with divergent content ({sim:.0%} body similarity)"

    if not b_ok and t_ok:
        return "HIGH", f"Test session has MORE access than baseline ({baseline.status} → {test.status})"

    if b_ok and not t_ok:
        return "INFO", f"Access correctly restricted ({baseline.status} → {test.status})"

    return "INFO", f"Both sessions restricted ({baseline.status}, {test.status})"


def _compare(url: str, bl: str, tl: str, br: HttpResponse, tr: HttpResponse) -> Finding:
    sim = _similarity(br.body, tr.body)
    sev, reason = _severity(br, tr, sim)
    json_diffs: List[str] = []
    diff_lines: List[str] = []
    if br.is_json and tr.is_json:
        json_diffs = _json_diff(br.json_data, tr.json_data)
    else:
        diff_lines = _text_diff(br.body, tr.body, bl, tl)
    return Finding(
        url=url, baseline=bl, test=tl,
        severity=sev, reason=reason,
        baseline_resp=br, test_resp=tr,
        similarity=sim,
        diff_lines=diff_lines,
        json_diffs=json_diffs,
    )


# ── URL worker ────────────────────────────────────────────────────────────────

def test_url(
    url: str,
    auth_states: List[AuthState],
    baseline_label: str,
    delay: float,
    timeout: int,
    verify_ssl: bool,
) -> List[Finding]:
    sess = _make_http_session(verify_ssl)
    responses: Dict[str, HttpResponse] = {}

    with _host_lock(url):
        for state in auth_states:
            responses[state.label] = _fetch(sess, url, state.headers, timeout)
            if delay > 0:
                time.sleep(delay)

    baseline = responses.get(baseline_label)
    if baseline is None:
        return []

    return [
        _compare(url, baseline_label, s.label, baseline, responses[s.label])
        for s in auth_states
        if s.label != baseline_label
    ]


# ── Diff HTML report ──────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

_DIFF_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Diffy — Diff Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:28px}}
  h1{{color:#58a6ff;font-size:1.5rem;margin-bottom:6px}}
  .meta{{color:#8b949e;font-size:.8rem;margin-bottom:28px;line-height:1.7}}
  .meta span{{margin-right:18px}}
  .stats{{display:flex;gap:16px;margin-bottom:36px;flex-wrap:wrap}}
  .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 22px;min-width:130px}}
  .stat-label{{color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}}
  .stat-value{{font-size:1.9rem;font-weight:700;margin-top:4px}}
  .crit{{color:#f85149}} .high{{color:#e3b341}} .med{{color:#58a6ff}}
  .info{{color:#8b949e}} .ok{{color:#3fb950}}
  .section-title{{color:#58a6ff;font-size:1rem;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #21262d}}
  details.finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:10px;overflow:hidden}}
  details.finding summary{{list-style:none;display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer;flex-wrap:wrap}}
  details.finding summary::-webkit-details-marker{{display:none}}
  details.finding summary:hover{{background:#1c2128}}
  .badge{{font-size:.7rem;font-weight:700;padding:2px 8px;border-radius:4px;letter-spacing:.05em;white-space:nowrap}}
  .badge-CRITICAL{{background:#f85149;color:#fff}}
  .badge-HIGH{{background:#e3b341;color:#000}}
  .badge-MEDIUM{{background:#1f6feb;color:#fff}}
  .badge-INFO{{background:#21262d;color:#8b949e}}
  .f-url{{color:#e6edf3;font-size:.82rem;flex:1;word-break:break-all}}
  .f-meta{{color:#8b949e;font-size:.75rem;white-space:nowrap}}
  .f-body{{padding:0 16px 16px;border-top:1px solid #21262d}}
  .reason{{color:#c9d1d9;font-size:.8rem;margin:12px 0 14px;padding:8px 12px;
           background:#0d1117;border-left:3px solid #30363d;border-radius:0 4px 4px 0}}
  .sim-wrap{{height:3px;background:#21262d;border-radius:2px;margin-bottom:14px}}
  .sim-bar{{height:3px;border-radius:2px;background:#3fb950}}
  .responses{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}}
  @media(max-width:680px){{.responses{{grid-template-columns:1fr}}}}
  .rbox{{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px 12px}}
  .rlabel{{font-size:.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:5px}}
  .rstatus{{font-size:1rem;font-weight:700;margin-bottom:3px}}
  .rmeta{{font-size:.7rem;color:#8b949e;margin-bottom:8px}}
  .rbody{{font-size:.7rem;color:#c9d1d9;white-space:pre-wrap;word-break:break-all;
          max-height:200px;overflow-y:auto;border-top:1px solid #21262d;padding-top:8px}}
  details.diff-detail summary{{color:#58a6ff;font-size:.75rem;padding:4px 0;list-style:none;cursor:pointer}}
  details.diff-detail summary::-webkit-details-marker{{display:none}}
  details.diff-detail summary::before{{content:"▶ "}}
  details.diff-detail[open] summary::before{{content:"▼ "}}
  .diff-block{{background:#0d1117;border:1px solid #21262d;border-radius:6px;
               padding:10px 12px;margin-top:6px;font-size:.7rem;
               white-space:pre;overflow-x:auto;max-height:280px;overflow-y:auto;line-height:1.5}}
  .da{{color:#3fb950;display:block}} .dr{{color:#f85149;display:block}}
  .dh{{color:#58a6ff;display:block}} .dc{{color:#6e7681;display:block}}
  .empty{{color:#8b949e;font-size:.85rem;padding:24px;text-align:center}}
</style>
</head>
<body>
<h1>Diffy &mdash; Diff Report</h1>
<p class="meta">
  <span>Generated: {timestamp}</span>
  <span>URLs: {total_urls}</span>
  <span>Baseline: <strong>{baseline}</strong></span>
  <span>Sessions: {sessions}</span>
</p>
<div class="stats">
  <div class="stat"><div class="stat-label">Critical</div><div class="stat-value crit">{n_crit}</div></div>
  <div class="stat"><div class="stat-label">High</div><div class="stat-value high">{n_high}</div></div>
  <div class="stat"><div class="stat-label">Medium</div><div class="stat-value med">{n_med}</div></div>
  <div class="stat"><div class="stat-label">Info</div><div class="stat-value info">{n_info}</div></div>
</div>
<p class="section-title">Findings</p>
<div id="findings">
{findings_html}
</div>
</body>
</html>
"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _status_cls(code: int) -> str:
    if code == 0:
        return "info"
    if 200 <= code < 300:
        return "ok"
    if 400 <= code < 500:
        return "info"
    return "high"


def _render_diff_block(diff_lines: List[str]) -> str:
    parts: List[str] = []
    for line in diff_lines:
        e = _esc(line.rstrip("\n"))
        if line.startswith("+") and not line.startswith("+++"):
            parts.append(f'<span class="da">{e}</span>')
        elif line.startswith("-") and not line.startswith("---"):
            parts.append(f'<span class="dr">{e}</span>')
        elif line.startswith("@@"):
            parts.append(f'<span class="dh">{e}</span>')
        else:
            parts.append(f'<span class="dc">{e}</span>')
    return "".join(parts)


def _render_resp(label: str, r: HttpResponse) -> str:
    if r.error:
        status_html = f'<div class="rstatus info">ERR</div>'
        body_html = f'<div class="rbody">{_esc(r.error)}</div>'
    else:
        sc = _status_cls(r.status)
        status_html = f'<div class="rstatus {sc}">{r.status}</div>'
        body_html = f'<div class="rbody">{_esc(r.body[:1500])}</div>'
    meta = f'{_esc(r.content_type[:50] or "—")} &bull; {r.size}B &bull; {r.elapsed_ms}ms'
    return (
        f'<div class="rbox">'
        f'<div class="rlabel">{_esc(label)}</div>'
        f'{status_html}'
        f'<div class="rmeta">{meta}</div>'
        f'{body_html}'
        f'</div>'
    )


def _render_finding(f: Finding) -> str:
    sim_pct = int(f.similarity * 100)
    open_attr = " open" if f.severity != "INFO" else ""

    diff_section = ""
    if f.json_diffs:
        body = _esc("\n".join(f.json_diffs))
        diff_section = (
            f'<details class="diff-detail"><summary>JSON structural diff '
            f'({len(f.json_diffs)} difference(s))</summary>'
            f'<div class="diff-block">{body}</div></details>'
        )
    elif f.diff_lines:
        body = _render_diff_block(f.diff_lines)
        diff_section = (
            f'<details class="diff-detail"><summary>Unified diff</summary>'
            f'<div class="diff-block">{body}</div></details>'
        )

    return (
        f'<details class="finding"{open_attr}>'
        f'<summary>'
        f'<span class="badge badge-{f.severity}">{f.severity}</span>'
        f'<span class="f-url">{_esc(f.url)}</span>'
        f'<span class="f-meta">{_esc(f.baseline)} &rarr; {_esc(f.test)} &bull; {sim_pct}% similar</span>'
        f'</summary>'
        f'<div class="f-body">'
        f'<div class="reason">{_esc(f.reason)}</div>'
        f'<div class="sim-wrap"><div class="sim-bar" style="width:{sim_pct}%"></div></div>'
        f'<div class="responses">'
        f'{_render_resp(f.baseline, f.baseline_resp)}'
        f'{_render_resp(f.test, f.test_resp)}'
        f'</div>'
        f'{diff_section}'
        f'</div>'
        f'</details>'
    )


def build_diff_report(
    findings: List[Finding],
    output_path: Path,
    total_urls: int,
    baseline_label: str,
    auth_states: List[AuthState],
) -> None:
    sorted_f = sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity, 99))
    counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    findings_html = (
        "\n".join(_render_finding(f) for f in sorted_f)
        if sorted_f
        else '<p class="empty">No findings.</p>'
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        _DIFF_HTML.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_urls=total_urls,
            baseline=_esc(baseline_label),
            sessions=_esc(", ".join(s.label for s in auth_states)),
            n_crit=counts["CRITICAL"],
            n_high=counts["HIGH"],
            n_med=counts["MEDIUM"],
            n_info=counts["INFO"],
            findings_html=findings_html,
        ),
        encoding="utf-8",
    )


# ── Report server ─────────────────────────────────────────────────────────────

def _hyperlink(url: str, text: str) -> str:
    """OSC 8 ANSI hyperlink — clickable in most modern terminals."""
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


def _serve_report(report_path: Path, port: int) -> None:
    """Serve the report directory on localhost. Blocks until Ctrl+C."""
    directory = str(report_path.parent.resolve())

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)
        def log_message(self, *args):
            pass

    class _Server(socketserver.TCPServer):
        allow_reuse_address = True

    with _Server(("127.0.0.1", port), _Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


# ── Diff command ──────────────────────────────────────────────────────────────

def load_urls(path: Path) -> List[str]:
    return [
        ln.strip()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


def cmd_diff(args: argparse.Namespace) -> None:
    if not args.url_file.is_file():
        print(f"[!] URL file not found: {args.url_file}", file=sys.stderr)
        sys.exit(1)

    urls = load_urls(args.url_file)
    if not urls:
        print("[!] URL file is empty.")
        sys.exit(0)

    if args.no_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    auth_states = build_auth_states(args.auth or [], args.sessions_file)
    labels = [s.label for s in auth_states]

    if args.baseline not in labels:
        print(f"[!] Baseline '{args.baseline}' not in sessions: {labels}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Diffy diff — {args.url_file}")
    print(f"  {'─'*44}")
    print(f"  URLs      : {len(urls)}")
    print(f"  Sessions  : {', '.join(labels)}")
    print(f"  Baseline  : {args.baseline}")
    print(f"  Workers   : {args.workers}")
    print(f"  Delay     : {args.delay}s / host")
    print(f"  Timeout   : {args.timeout}s")
    print(f"  SSL verify: {not args.no_verify}")
    print()

    t0 = time.perf_counter()
    all_findings: List[Finding] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                test_url, url, auth_states, args.baseline,
                args.delay, args.timeout, not args.no_verify,
            ): url
            for url in urls
        }
        alerts: List[str] = []
        errors: List[str] = []
        with tqdm(total=len(urls), desc="  Testing  ", unit="url", ncols=68,
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]") as bar:
            for fut in as_completed(futures):
                try:
                    findings = fut.result()
                    all_findings.extend(findings)
                    for f in findings:
                        if f.severity in ("CRITICAL", "HIGH"):
                            alerts.append(f"  [!] {f.severity:<8} {f.test} → {f.url}")
                except Exception as exc:
                    errors.append(f"  [ERR] {exc}")
                bar.update(1)

    print()
    for line in alerts:
        print(line)
    for line in errors:
        print(line)
    if alerts or errors:
        print()

    print("[*] Building diff report…")
    build_diff_report(
        findings=all_findings,
        output_path=args.output,
        total_urls=len(urls),
        baseline_label=args.baseline,
        auth_states=auth_states,
    )

    elapsed = time.perf_counter() - t0
    counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    report_url = f"http://localhost:{args.serve_port}/{args.output.name}"

    print(f"\n  {'─'*44}")
    print(f"  URLs      : {len(urls)}")
    print(f"  CRITICAL  : {counts['CRITICAL']}")
    print(f"  HIGH      : {counts['HIGH']}")
    print(f"  MEDIUM    : {counts['MEDIUM']}")
    print(f"  INFO      : {counts['INFO']}")
    print(f"  Elapsed   : {elapsed:.2f}s")
    print(f"  {'─'*44}")

    if not args.no_serve:
        print(f"\n  Serving on {_hyperlink(report_url, report_url)}")
        print(f"  Ctrl+C to stop\n")
        _serve_report(args.output, args.serve_port)
    else:
        print(f"  Report -> {args.output}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="diffy",
        description="Synack Red Team triage — screenshot dedup and HTTP access-control diffing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python diffy.py scan ./screenshots
  python diffy.py scan ./shots --threshold 8 --mask 0,0,1920,60

  python diffy.py diff urls.txt --auth admin:Cookie:session=abc \\
                                --auth user:Cookie:session=def  \\
                                --auth anon::                   \\
                                --baseline admin

  python diffy.py diff urls.txt --sessions-file sessions.json --baseline admin

sessions.json format:
  {
    "admin": {"Cookie": "session=abc", "X-Role": "admin"},
    "user":  {"Cookie": "session=def"},
    "anon":  {}
  }
""",
    )
    sub = root.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="Visual screenshot deduplication (pHash)")
    sp.add_argument("directory", type=Path, help="Directory of screenshots")
    sp.add_argument("--threshold", "-t", type=int, default=5, metavar="BITS",
                    help="Hamming distance threshold (default: 5)")
    sp.add_argument("--workers", "-w", type=int, default=4, metavar="N",
                    help="Parallel threads (default: 4)")
    sp.add_argument("--mask", "-m", dest="masks", type=parse_mask,
                    action="append", default=[], metavar="x1,y1,x2,y2",
                    help="Pixel region to ignore before hashing (repeatable)")
    sp.add_argument("--manifest", type=Path, default=Path("diffy_manifest.json"),
                    metavar="PATH", help="Hash cache file")
    sp.add_argument("--no-manifest", action="store_true", help="Skip manifest cache")
    sp.add_argument("--output", "-o", type=Path, default=Path("triage_report.html"),
                    metavar="PATH", help="Output HTML path")
    sp.add_argument("--extensions", nargs="+", default=["png", "jpg", "jpeg"],
                    metavar="EXT", help="File extensions to process")

    # ── diff ──────────────────────────────────────────────────────────────────
    dp = sub.add_parser("diff", help="HTTP differential access-control testing (IDOR/BOLA)")
    dp.add_argument("url_file", type=Path,
                    help="File with one URL per line (# = comment)")
    dp.add_argument("--auth", "-a", dest="auth", type=parse_auth_arg,
                    action="append", metavar="label:HeaderName:HeaderValue",
                    help=(
                        "Auth session (repeatable). "
                        "E.g. --auth admin:Cookie:session=abc  "
                        "     --auth anon:: "
                        "(multiple --auth with the same label add multiple headers)"
                    ))
    dp.add_argument("--sessions-file", type=Path, default=None, metavar="PATH",
                    help="JSON sessions file (see epilog for format)")
    dp.add_argument("--baseline", "-b", required=True, metavar="LABEL",
                    help="Session label for the authorized reference state")
    dp.add_argument("--workers", "-w", type=int, default=4, metavar="N",
                    help="Parallel URL workers (default: 4)")
    dp.add_argument("--delay", "-d", type=float, default=0.3, metavar="SEC",
                    help="Delay between requests to the same host (default: 0.3s)")
    dp.add_argument("--timeout", type=int, default=10, metavar="SEC",
                    help="Per-request timeout (default: 10s)")
    dp.add_argument("--no-verify", action="store_true",
                    help="Disable SSL certificate verification")
    dp.add_argument("--output", "-o", type=Path, default=Path("diff_report.html"),
                    metavar="PATH", help="Output HTML path")
    dp.add_argument("--no-serve", action="store_true",
                    help="Skip auto-hosting the report (just write the file)")
    dp.add_argument("--serve-port", type=int, default=7771, metavar="PORT",
                    help="Port to serve the report on (default: 7771)")

    return root


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "scan":
        cmd_scan(args)
    else:
        cmd_diff(args)


if __name__ == "__main__":
    main()
