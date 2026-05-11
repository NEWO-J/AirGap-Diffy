# diffy — Demo Environment

A self-contained test environment with two components:

- **`app.py`** — intentionally vulnerable Flask app for testing `diffy diff`
- **`gen_screenshots.py`** — generates sample screenshots for testing `diffy scan`

All commands are run from the **repo root**, not from inside `demo/`.

---

## Setup

```bash
pip install -r requirements.txt       # diffy dependencies
pip install -r demo/requirements.txt  # Flask (demo app only)
```

---

## Testing `diffy scan`

Generate 22 sample screenshots (5 page types × 4 near-duplicate variants + 2 unique error pages):

```bash
python demo/gen_screenshots.py
```

Run the deduplicator:

```bash
python diffy.py scan demo/screenshots/ --output demo/scan_report.html
```

Open `demo/scan_report.html` — you should see ~7 unique images instead of 22.

**Testing the mask feature:**

Each screenshot has a rotating timestamp in the browser chrome at pixel region `(1100, 36, 1280, 80)`. Without masking, the tool may treat near-duplicate variants as unique because the timestamp differs. Masking suppresses it:

```bash
python diffy.py scan demo/screenshots/ \
  --mask 1100,36,1280,80 \
  --output demo/scan_report_masked.html
```

Compare the two reports — the masked version should filter more aggressively.

---

## Testing `diffy diff`

**Terminal 1** — start the demo app (keep it running):

```bash
python demo/app.py
```

**Terminal 2** — run the diff against all sessions:

```bash
python diffy.py diff demo/urls.txt \
  --sessions-file demo/sessions.json \
  --baseline admin \
  --output demo/diff_report.html
```

Open `demo/diff_report.html`.

---

## Expected findings

| Endpoint | Severity | Vulnerability |
|---|---|---|
| `GET /api/users/1` | **CRITICAL** | No auth check — anon gets full object including SSN |
| `GET /api/users/2` | **CRITICAL** | Same — complete IDOR |
| `GET /api/admin/users` | **CRITICAL** | Admin route with zero access control |
| `GET /api/orders/101` | **HIGH** | Auth required but no ownership check (BOLA) |
| `GET /api/orders/102` | **HIGH** | Alice reads Bob's order, Bob reads Alice's |
| `GET /api/orders/103` | **HIGH** | Cross-user access to admin's order |
| `GET /api/me` | **HIGH*** | False positive — see note below |
| `GET /api/documents/201` | Info | Correctly 403'd for non-owner (secure) |
| `GET /api/documents/202` | Info | Correctly 403'd for non-owner (secure) |
| `GET /api/admin/audit-log` | Info | Correctly 403'd for non-admin (secure) |
| `GET /health` | Info | Public — all sessions identical |

**\* False positive on `/api/me`:** Each session legitimately receives its own user record. The JSON structure is identical across sessions (same keys, different values), which pushes similarity above the HIGH threshold. The tool cannot distinguish "each user sees their own data" from "user B sees user A's data" — that determination requires human review. This is a known limitation of structure-based diffing.

---

## Demo sessions

| Label | Token | Role |
|---|---|---|
| `admin` | `admin-token-demo` | admin |
| `alice` | `alice-token-demo` | user (id=1) |
| `bob` | `bob-token-demo` | user (id=2) |
| `anon` | *(no cookie)* | unauthenticated |

You can also pass sessions inline instead of using the JSON file:

```bash
python diffy.py diff demo/urls.txt \
  --auth admin:Cookie:session=admin-token-demo \
  --auth alice:Cookie:session=alice-token-demo \
  --auth anon:: \
  --baseline admin \
  --output demo/diff_report.html
```
