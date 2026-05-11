# AirGap-Diffy

Penetration testing triage tool built for Synack Red Team with two modes: visual screenshot deduplication via Perceptual Hashing, and differential HTTP access-control testing for IDOR/BOLA detection. All processing is local, no external API calls, no cloud uploads. 

---

## Install

```bash
pip install -r requirements.txt
```

---

## `scan` — Screenshot deduplication

Hashes every screenshot in a directory using pHash, groups visually identical images by Hamming distance, and outputs a self-contained HTML report of only the unique ones.

Designed for GoWitness / Aquatone / EyeWitness output where 80%+ of screenshots are the same login page.

```bash
python diffy.py scan ./screenshots
```

```bash
# Tighter dedup, more threads
python diffy.py scan ./shots --threshold 8 --workers 8

# Mask a rotating top banner and footer clock on 1920x1080 targets
python diffy.py scan ./shots \
  --mask 0,0,1920,60 \
  --mask 0,980,1920,1080

# Persist hashes across runs — skips already-processed files
python diffy.py scan ./shots --manifest ~/.diffy/hashes.json

# One-off run, write nothing to disk except the report
python diffy.py scan ./shots --no-manifest
```

**Output:** `triage_report.html` — self-contained, embeds all images as base64.

### Threshold guide

| Distance | Meaning |
|---|---|
| 0 | Exact pixel match |
| 1–3 | JPEG re-saves, minor compression artifacts |
| **5** | **Default** — same page, minor UI state differences |
| 8–10 | Same app, different data loaded |
| 12+ | May collapse distinct targets |

### Options

| Flag | Default | Description |
|---|---|---|
| `--threshold` / `-t` | `5` | Hamming distance cutoff for duplicates |
| `--workers` / `-w` | `4` | Parallel hashing threads |
| `--mask` / `-m` | — | `x1,y1,x2,y2` region to black out before hashing (repeatable) |
| `--manifest` | `diffy_manifest.json` | Hash cache file for incremental runs |
| `--no-manifest` | — | Disable caching |
| `--output` / `-o` | `triage_report.html` | Output path |
| `--extensions` | `png jpg jpeg` | File types to process |

---

## `diff` — HTTP access-control testing

Replays a URL list under multiple auth sessions simultaneously, diffs the responses structurally, and flags access-control breaks. Targets IDOR and BOLA — cases where a lower-privileged session receives the same data as the authorized one.

```bash
python diffy.py diff urls.txt \
  --auth admin:Cookie:session=abc123 \
  --auth user:Cookie:session=def456  \
  --auth anon::                      \
  --baseline admin
```

`urls.txt` — one URL per line, `#` comments ignored:

```
# Account endpoints
https://target.com/api/v1/users/1337
https://target.com/api/v1/users/1338
https://target.com/api/v1/orders/9001
```

### Auth session formats

**CLI** — `label:HeaderName:HeaderValue`, split on first two colons:

```bash
# Cookie auth
--auth admin:Cookie:session=abc123

# Bearer token
--auth admin:Authorization:Bearer eyJhbGc...

# No auth (unauthenticated baseline)
--auth anon::
```

Multiple `--auth` flags with the same label stack headers for that session:

```bash
--auth admin:Cookie:session=abc \
--auth admin:X-CSRF-Token:xyz
```

**JSON file** — use `--sessions-file` for complex or many-header sessions:

```bash
python diffy.py diff urls.txt --sessions-file sessions.json --baseline admin
```

```json
{
  "admin": { "Cookie": "session=abc123", "X-CSRF-Token": "xyz" },
  "user":  { "Cookie": "session=def456", "X-CSRF-Token": "xyz" },
  "anon":  {}
}
```

### Severity model

Each non-baseline session is compared against the baseline response for every URL:

| Condition | Severity |
|---|---|
| Test 2xx, body ≥ 85% similar to baseline 2xx | **CRITICAL** |
| Test 2xx, body 55–84% similar to baseline 2xx | **HIGH** |
| Test 2xx, body < 55% similar to baseline 2xx | **MEDIUM** |
| Test has more access than baseline (baseline 4xx → test 2xx) | **HIGH** |
| Access correctly denied (baseline 2xx → test 4xx) | INFO |
| Both sessions denied | Info |

**Output:** `diff_report.html` — findings sorted by severity, collapsible per entry, side-by-side response bodies with JSON structural diff or unified text diff.

CRITICAL/HIGH/MEDIUM findings are expanded by default. INFO is collapsed.

### Options

| Flag | Default | Description |
|---|---|---|
| `--auth` / `-a` | — | Session definition `label:HeaderName:HeaderValue` (repeatable) |
| `--sessions-file` | — | JSON sessions file |
| `--baseline` / `-b` | required | Label of the authorized reference session |
| `--workers` / `-w` | `4` | Parallel URL workers |
| `--delay` / `-d` | `0.3s` | Delay between requests to the same host |
| `--timeout` | `10s` | Per-request timeout |
| `--no-verify` | — | Disable SSL certificate verification |
| `--output` / `-o` | `diff_report.html` | Output path |

---

## Demo

A self-contained demo environment lives in `demo/` with an intentionally vulnerable Flask app and a screenshot generator.

```bash
pip install -r requirements.txt
pip install -r demo/requirements.txt
```

**Test `scan`** — generate near-duplicate screenshots and dedup them:

```bash
python demo/gen_screenshots.py
python diffy.py scan demo/screenshots/ --output demo/scan_report.html
```

**Test `diff`** — start the demo app in one terminal, run the diff in another:

```bash
# Terminal 1
python demo/app.py

# Terminal 2
python diffy.py diff demo/urls.txt \
  --sessions-file demo/sessions.json \
  --baseline admin \
  --output demo/diff_report.html
```

See [`demo/README.md`](demo/README.md) for the full expected findings breakdown.

---

## RoE compliance

- Zero outbound calls beyond the target URLs you supply.
- `requests` uses only direct TCP connections to your specified targets — no proxies, no analytics, no telemetry.
- The manifest stores only file paths and pHash hex strings — no image data.
- `--no-manifest` leaves no artifacts on disk beyond the HTML report.
