#!/usr/bin/env python3
"""
demo/app.py — Intentionally vulnerable Flask app for testing diffy diff.

DO NOT deploy outside of localhost. Every vulnerability here is deliberate.

Sessions (use in sessions.json or --auth flags):
  admin-token-demo  →  admin role, user_id=0
  alice-token-demo  →  user  role, user_id=1
  bob-token-demo    →  user  role, user_id=2
  (no cookie)       →  unauthenticated
"""
import secrets
from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Fake data ─────────────────────────────────────────────────────────────────

SESSIONS = {
    "admin-token-demo": {"user_id": 0, "role": "admin", "name": "Admin"},
    "alice-token-demo": {"user_id": 1, "role": "user",  "name": "Alice"},
    "bob-token-demo":   {"user_id": 2, "role": "user",  "name": "Bob"},
}

USERS = {
    0: {
        "id": 0,
        "name": "Admin",
        "email": "admin@target.local",
        "role": "admin",
        "phone": "555-0100",
        "ssn": "000-00-0000",
        "address": {"street": "1 Admin Blvd", "city": "Springfield", "state": "IL", "zip": "62701"},
        "created_at": "2019-03-15T08:00:00Z",
        "last_login": "2026-05-12T09:14:22Z",
        "mfa_enabled": True,
        "api_key": "sk-adm-a1b2c3d4e5f6",
        "permissions": ["read", "write", "delete", "admin"],
        "account_balance": "$0.00",
    },
    1: {
        "id": 1,
        "name": "Alice",
        "email": "alice@target.local",
        "role": "user",
        "phone": "555-0101",
        "ssn": "111-22-3333",
        "address": {"street": "42 Elm Street", "city": "Shelbyville", "state": "IL", "zip": "62565"},
        "created_at": "2021-07-04T14:30:00Z",
        "last_login": "2026-05-11T18:45:10Z",
        "mfa_enabled": False,
        "api_key": "sk-usr-f9e8d7c6b5a4",
        "permissions": ["read", "write"],
        "account_balance": "$149.50",
    },
    2: {
        "id": 2,
        "name": "Bob",
        "email": "bob@target.local",
        "role": "user",
        "phone": "555-0102",
        "ssn": "444-55-6666",
        "address": {"street": "7 Oak Avenue", "city": "Capital City", "state": "IL", "zip": "62702"},
        "created_at": "2022-01-20T11:00:00Z",
        "last_login": "2026-05-10T07:22:55Z",
        "mfa_enabled": False,
        "api_key": "sk-usr-1a2b3c4d5e6f",
        "permissions": ["read", "write"],
        "account_balance": "$87.20",
    },
}

ORDERS = {
    101: {
        "id": 101, "owner_id": 1, "status": "shipped",
        "item": "Widget A", "quantity": 2, "unit_price": "$24.99", "total": "$49.98",
        "card_last4": "4242", "card_brand": "Visa", "billing_zip": "62565",
        "shipping_address": {"name": "Alice", "street": "42 Elm Street", "city": "Shelbyville", "state": "IL", "zip": "62565"},
        "tracking": "1Z999AA10123456784",
        "created_at": "2026-04-30T10:15:00Z",
        "shipped_at": "2026-05-02T14:00:00Z",
    },
    102: {
        "id": 102, "owner_id": 2, "status": "delivered",
        "item": "Widget B", "quantity": 1, "unit_price": "$29.99", "total": "$29.99",
        "card_last4": "1337", "card_brand": "Mastercard", "billing_zip": "62702",
        "shipping_address": {"name": "Bob", "street": "7 Oak Avenue", "city": "Capital City", "state": "IL", "zip": "62702"},
        "tracking": "9400111899223397623910",
        "created_at": "2026-05-01T08:30:00Z",
        "shipped_at": "2026-05-03T09:00:00Z",
    },
    103: {
        "id": 103, "owner_id": 0, "status": "processing",
        "item": "Widget C (Enterprise)", "quantity": 10, "unit_price": "$9.99", "total": "$99.90",
        "card_last4": "0000", "card_brand": "Amex", "billing_zip": "62701",
        "shipping_address": {"name": "Admin", "street": "1 Admin Blvd", "city": "Springfield", "state": "IL", "zip": "62701"},
        "tracking": None,
        "created_at": "2026-05-12T07:00:00Z",
        "shipped_at": None,
    },
}

DOCUMENTS = {
    201: {
        "id": 201, "owner_id": 1,
        "title": "Alice Master Service Agreement",
        "classification": "CONFIDENTIAL",
        "body": (
            "CONFIDENTIAL — This Master Service Agreement ('Agreement') is entered into "
            "as of January 1, 2024, between Alice (user_id=1) and the service provider. "
            "This agreement governs use of all platform services and supersedes all prior agreements. "
            "Unauthorized access or disclosure of this document is strictly prohibited."
        ),
        "signed_at": "2024-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
        "version": "3.1",
    },
    202: {
        "id": 202, "owner_id": 2,
        "title": "Bob Master Service Agreement",
        "classification": "CONFIDENTIAL",
        "body": (
            "CONFIDENTIAL — This Master Service Agreement ('Agreement') is entered into "
            "as of March 15, 2024, between Bob (user_id=2) and the service provider. "
            "This agreement governs use of all platform services and supersedes all prior agreements. "
            "Unauthorized access or disclosure of this document is strictly prohibited."
        ),
        "signed_at": "2024-03-15T00:00:00Z",
        "expires_at": "2027-03-15T00:00:00Z",
        "version": "3.1",
    },
}


def current_session():
    for part in request.headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith("session="):
            return SESSIONS.get(part[8:].strip())
    return None


def api_ok(data):
    """Wrap a successful response with per-request metadata (CSRF token, request ID)."""
    return jsonify({
        "data": data,
        "_meta": {
            "csrf_token": secrets.token_hex(16),
            "request_id": secrets.token_hex(8),
        },
    })


# ── Public ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Public. All sessions receive the same response — expect INFO."""
    return jsonify({"status": "ok", "service": "diffy-demo", "version": "1.0.0"})


# ── VULNERABLE endpoints ──────────────────────────────────────────────────────

@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    """
    VULNERABLE — IDOR (no auth check whatsoever).
    Unauthenticated and cross-user sessions receive the full user object.
    Expect CRITICAL (anon) / HIGH (cross-user). CSRF token causes <100% similarity.
    """
    user = USERS.get(user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    return api_ok(user)


@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    """
    VULNERABLE — BOLA (authenticated but no ownership check).
    Any logged-in user can read any order regardless of owner_id.
    Expect HIGH for cross-session reads.
    """
    sess = current_session()
    if not sess:
        return jsonify({"error": "unauthorized"}), 401
    order = ORDERS.get(order_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    # BUG: missing check → order["owner_id"] != sess["user_id"]
    return api_ok(order)


@app.route("/api/admin/users")
def admin_list_users():
    """
    VULNERABLE — Broken access control (admin route, zero auth enforcement).
    Expect CRITICAL for all non-admin sessions including unauthenticated.
    """
    return api_ok({"users": list(USERS.values()), "total": len(USERS)})


# ── SECURE endpoints ──────────────────────────────────────────────────────────

@app.route("/api/documents/<int:doc_id>")
def get_document(doc_id):
    """
    SECURE — Ownership enforced correctly.
    Non-owners receive 403. Expect INFO findings (access correctly denied).
    """
    sess = current_session()
    if not sess:
        return jsonify({"error": "unauthorized"}), 401
    doc = DOCUMENTS.get(doc_id)
    if doc is None:
        return jsonify({"error": "not found"}), 404
    if doc["owner_id"] != sess["user_id"] and sess["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    return api_ok(doc)


@app.route("/api/admin/audit-log")
def admin_audit_log():
    """
    SECURE — Role check enforced.
    Non-admin sessions receive 403. Expect INFO findings.
    """
    sess = current_session()
    if not sess:
        return jsonify({"error": "unauthorized"}), 401
    if sess["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    return api_ok({
        "events": [
            {"action": "login",       "user": "alice", "ts": "2026-05-12T08:01:44Z"},
            {"action": "login",       "user": "bob",   "ts": "2026-05-12T08:14:09Z"},
            {"action": "view",        "user": "alice", "ts": "2026-05-12T08:02:11Z", "resource": "/api/orders/101"},
            {"action": "view",        "user": "bob",   "ts": "2026-05-12T08:15:33Z", "resource": "/api/orders/102"},
            {"action": "admin_view",  "user": "admin", "ts": "2026-05-12T09:14:22Z", "resource": "/api/admin/users"},
        ],
        "count": 5,
    })


@app.route("/api/me")
def me():
    """
    SECURE by design — always returns the caller's own record.
    Will surface as HIGH because JSON structure matches across sessions but
    values differ. This is a known false positive pattern — requires human triage.
    """
    sess = current_session()
    if not sess:
        return jsonify({"error": "unauthorized"}), 401
    return api_ok(USERS[sess["user_id"]])


if __name__ == "__main__":
    print("\n  diffy demo app — http://localhost:5000")
    print("  DO NOT expose outside localhost.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
