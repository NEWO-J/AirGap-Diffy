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
from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Fake data ─────────────────────────────────────────────────────────────────

SESSIONS = {
    "admin-token-demo": {"user_id": 0, "role": "admin", "name": "Admin"},
    "alice-token-demo": {"user_id": 1, "role": "user",  "name": "Alice"},
    "bob-token-demo":   {"user_id": 2, "role": "user",  "name": "Bob"},
}

USERS = {
    0: {"id": 0, "name": "Admin", "email": "admin@target.local", "role": "admin", "phone": "555-0100", "ssn": "000-00-0000"},
    1: {"id": 1, "name": "Alice", "email": "alice@target.local", "role": "user",  "phone": "555-0101", "ssn": "111-22-3333"},
    2: {"id": 2, "name": "Bob",   "email": "bob@target.local",   "role": "user",  "phone": "555-0102", "ssn": "444-55-6666"},
}

ORDERS = {
    101: {"id": 101, "owner_id": 1, "item": "Widget A", "total": "$49.99", "card_last4": "4242"},
    102: {"id": 102, "owner_id": 2, "item": "Widget B", "total": "$29.99", "card_last4": "1337"},
    103: {"id": 103, "owner_id": 0, "item": "Widget C", "total": "$99.99", "card_last4": "0000"},
}

DOCUMENTS = {
    201: {"id": 201, "owner_id": 1, "title": "Alice Contract", "body": "CONFIDENTIAL — Alice terms of service."},
    202: {"id": 202, "owner_id": 2, "title": "Bob Contract",   "body": "CONFIDENTIAL — Bob terms of service."},
}


def current_session():
    """Parse session token from Cookie header."""
    for part in request.headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith("session="):
            return SESSIONS.get(part[8:].strip())
    return None


# ── Public ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Public. All sessions receive the same response — expect INFO."""
    return jsonify({"status": "ok", "service": "diffy-demo"})


# ── VULNERABLE endpoints ──────────────────────────────────────────────────────

@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    """
    VULNERABLE — IDOR (no auth check whatsoever).
    Unauthenticated and cross-user sessions receive the full user object,
    including SSN and phone. Expect CRITICAL for anon, HIGH for cross-user.
    """
    user = USERS.get(user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    """
    VULNERABLE — BOLA (authenticated but no ownership check).
    Any logged-in user can read any order regardless of owner_id.
    Expect HIGH for alice reading bob's order and vice versa.
    """
    sess = current_session()
    if not sess:
        return jsonify({"error": "unauthorized"}), 401
    order = ORDERS.get(order_id)
    if order is None:
        return jsonify({"error": "not found"}), 404
    # BUG: missing check → order["owner_id"] != sess["user_id"]
    return jsonify(order)


@app.route("/api/admin/users")
def admin_list_users():
    """
    VULNERABLE — Broken access control (admin route, zero auth enforcement).
    Expect CRITICAL for all non-admin sessions including unauthenticated.
    """
    return jsonify({"users": list(USERS.values()), "total": len(USERS)})


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
    return jsonify(doc)


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
    return jsonify({
        "events": ["login:alice", "login:bob", "view:admin/users"],
        "count": 3,
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
    return jsonify(USERS[sess["user_id"]])


if __name__ == "__main__":
    print("\n  diffy demo app — http://localhost:5000")
    print("  DO NOT expose outside localhost.\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
