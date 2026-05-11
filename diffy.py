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
<title>Diffy Scan</title>
<style>
  body{{font-family:monospace;max-width:1400px;margin:32px auto;padding:0 20px;color:#111;font-size:13px}}
  h1{{font-size:1rem;margin-bottom:4px}}
  .m{{color:#666;margin-bottom:20px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}}
  .card{{border:1px solid #ddd;overflow:hidden}}
  .card img{{width:100%;display:block;height:140px;object-fit:cover;background:#f5f5f5}}
  .card p{{padding:5px 7px;margin:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .card small{{padding:0 7px 5px;display:block;color:#999}}
</style>
</head>
<body>
<h1>Diffy &mdash; Scan</h1>
<p class="m">{timestamp} &middot; {unique}/{total} unique &middot; {pct_saved}% filtered &middot; threshold {threshold}b{masks_meta}</p>
<div class="grid">
{cards}
</div>
</body>
</html>
"""

_SCAN_CARD = (
    '<div class="card">'
    '<img src="data:image/{fmt};base64,{b64}" alt="{name}" loading="lazy">'
    '<p title="{name}">{name}</p>'
    '<small>{phash}</small>'
    '</div>'
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
        f' &middot; masks: {"; ".join(str(m) for m in masks)}' if masks else ""
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
<title>Diffy Diff</title>
<style>
  body{{font-family:monospace;max-width:1200px;margin:32px auto;padding:0 20px;color:#111;font-size:13px}}
  h1{{font-size:1rem;margin-bottom:4px}}
  .m{{color:#666;margin-bottom:6px}}
  .counts{{display:flex;gap:20px;margin-bottom:18px;font-weight:bold}}
  .crit{{color:#c00}} .high{{color:#b55000}} .med{{color:#00c}} .info{{color:#999;font-weight:normal}}
  hr{{border:none;border-top:1px solid #ddd;margin:0}}
  details{{border-bottom:1px solid #eee}}
  details summary{{padding:7px 2px;cursor:pointer;display:flex;gap:10px;align-items:baseline;list-style:none;user-select:none}}
  details summary::-webkit-details-marker{{display:none}}
  details summary:hover{{background:#fafafa}}
  .sev{{font-weight:bold;min-width:68px;font-size:.8rem}}
  .fu{{flex:1;word-break:break-all}}
  .fw{{color:#555}} .fs{{color:#999}}
  .fb{{padding:8px 2px 14px}}
  .reason{{color:#555;margin-bottom:10px}}
  .pair{{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px}}
  @media(max-width:640px){{.pair{{grid-template-columns:1fr}}}}
  .rbox{{background:#f8f8f8;border:1px solid #e0e0e0;padding:7px 9px}}
  .rl{{color:#888;font-size:.7rem;text-transform:uppercase;margin-bottom:3px}}
  .rs{{font-weight:bold;margin-bottom:2px}}
  .rm{{color:#888;font-size:.75rem;margin-bottom:5px}}
  .rb{{white-space:pre-wrap;word-break:break-all;max-height:150px;overflow-y:auto;border-top:1px solid #e8e8e8;padding-top:5px;font-size:.8rem;color:#333}}
  details.dd summary{{color:#555;padding:3px 0;list-style:none;cursor:pointer}}
  details.dd summary::-webkit-details-marker{{display:none}}
  details.dd summary::before{{content:"▶ "}} details.dd[open] summary::before{{content:"▼ "}}
  pre{{background:#f8f8f8;border:1px solid #e0e0e0;padding:7px;overflow-x:auto;max-height:200px;overflow-y:auto;margin-top:4px;line-height:1.45;font-size:.8rem}}
  .da{{color:#060}} .dr{{color:#c00}} .dh{{color:#55f}} .dc{{color:#aaa}}
</style>
</head>
<body>
<h1>Diffy &mdash; Diff</h1>
<p class="m">{timestamp} &middot; baseline: <b>{baseline}</b> &middot; sessions: {sessions} &middot; {total_urls} URLs</p>
<div class="counts">
  <span class="crit">CRITICAL {n_crit}</span>
  <span class="high">HIGH {n_high}</span>
  <span class="med">MEDIUM {n_med}</span>
  <span class="info">INFO {n_info}</span>
</div>
<hr>
{findings_html}
</body>
</html>
"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _render_diff_block(diff_lines: List[str]) -> str:
    parts: List[str] = []
    for line in diff_lines:
        e = _esc(line.rstrip("\n"))
        if line.startswith("+") and not line.startswith("+++"):
            parts.append(f'<span class="da">{e}</span>\n')
        elif line.startswith("-") and not line.startswith("---"):
            parts.append(f'<span class="dr">{e}</span>\n')
        elif line.startswith("@@"):
            parts.append(f'<span class="dh">{e}</span>\n')
        else:
            parts.append(f'<span class="dc">{e}</span>\n')
    return "".join(parts)


def _render_resp(label: str, r: HttpResponse) -> str:
    if r.error:
        status = "ERR"
        meta = _esc(r.error[:80])
        body = ""
    else:
        status = str(r.status)
        meta = f'{_esc(r.content_type[:40] or "—")} &middot; {r.size}B &middot; {r.elapsed_ms}ms'
        body = f'<div class="rb">{_esc(r.body[:1200])}</div>'
    return (
        f'<div class="rbox">'
        f'<div class="rl">{_esc(label)}</div>'
        f'<div class="rs">{status}</div>'
        f'<div class="rm">{meta}</div>'
        f'{body}'
        f'</div>'
    )


def _render_finding(f: Finding) -> str:
    sim_pct = int(f.similarity * 100)
    open_attr = " open" if f.severity != "INFO" else ""
    sev_cls = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med"}.get(f.severity, "info")

    diff_html = ""
    if f.json_diffs:
        diff_html = (
            f'<details class="dd"><summary>JSON diff ({len(f.json_diffs)})</summary>'
            f'<pre>{_esc(chr(10).join(f.json_diffs))}</pre></details>'
        )
    elif f.diff_lines:
        diff_html = (
            f'<details class="dd"><summary>Unified diff</summary>'
            f'<pre>{_render_diff_block(f.diff_lines)}</pre></details>'
        )

    return (
        f'<details{open_attr}>'
        f'<summary>'
        f'<span class="sev {sev_cls}">{f.severity}</span>'
        f'<span class="fu">{_esc(f.url)}</span>'
        f'<span class="fw">{_esc(f.baseline)} &rarr; {_esc(f.test)}</span>'
        f'<span class="fs">{sim_pct}%</span>'
        f'</summary>'
        f'<div class="fb">'
        f'<div class="reason">{_esc(f.reason)}</div>'
        f'<div class="pair">{_render_resp(f.baseline, f.baseline_resp)}{_render_resp(f.test, f.test_resp)}</div>'
        f'{diff_html}'
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
        else "<p>No findings.</p>"
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
