"""Administrative command line.

  python -m backend.app.cli create-user --username alice --role investigator
  python -m backend.app.cli seed-demo          # synthetic demo accounts, case and evidence
  python -m backend.app.cli verify-audit
  python -m backend.app.cli single-account     # keep only the admin account active
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys

from backend.app import audit, db as dbm
from backend.app.config import ROOT, Settings
from backend.app.security import hash_password, password_policy


def _conn():
    s = Settings.from_env()
    dbm.init(s.db_path)
    return s, dbm.connect(s.db_path)


def _create(c, username, password, role, display=None) -> bool:
    if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return False
    c.execute("INSERT INTO users (username, pw_hash, role, display_name, created_at) VALUES (?,?,?,?,?)",
              (username, hash_password(password), role, display, dbm.now()))
    c.commit()
    audit.record(c, "cli", "user.create", f"user/{username}", {"role": role})
    return True


def create_user(args):
    _, c = _conn()
    pw = os.getenv("MIRQAB_NEW_USER_PASSWORD") or getpass.getpass("Password: ")
    if (msg := password_policy(pw)):
        sys.exit(msg)
    print("created" if _create(c, args.username, pw, args.role, args.display_name) else "user already exists")


def seed_demo(_args):
    """Create demo users (passwords from env or generated) and a synthetic case via the API layer."""
    s, c = _conn()
    creds = {}
    for user, role, env in (("investigator", "investigator", "MIRQAB_DEMO_INVESTIGATOR_PASSWORD"),
                            ("reviewer", "reviewer", "MIRQAB_DEMO_REVIEWER_PASSWORD"),
                            ("admin", "admin", "MIRQAB_DEMO_ADMIN_PASSWORD")):
        pw = os.getenv(env) or (secrets.token_urlsafe(9) + "7a")
        if _create(c, user, pw, role, f"Demo {role}"):
            creds[user] = pw
    from fastapi.testclient import TestClient
    from backend.app.main import create_app
    app = create_app(s)
    data = json.loads((ROOT / "sample_data" / "demo_case.json").read_text(encoding="utf-8"))
    with TestClient(app) as tc:
        pw = creds.get("investigator") or os.getenv("MIRQAB_DEMO_INVESTIGATOR_PASSWORD")
        if not pw:
            print("Demo users already exist; set MIRQAB_DEMO_INVESTIGATOR_PASSWORD to seed another demo case.")
        else:
            tok = tc.post("/api/auth/login", json={"username": "investigator", "password": pw}).json()["token"]
            h = {"Authorization": f"Bearer {tok}"}
            cid = tc.post("/api/cases", json={"title": data["title"], "description": data["description"]}, headers=h).json()["id"]
            for ev in data["evidence"]:
                tc.post(f"/api/cases/{cid}/evidence/text", json=ev, headers=h)
            for f in data.get("files", []):
                p = ROOT / "sample_data" / f["path"]
                tc.post(f"/api/cases/{cid}/evidence/file", files={"file": (p.name, p.read_bytes())},
                        data={"label": f["label"]}, headers=h)
            tc.post(f"/api/cases/{cid}/analyze", headers=h)
            print(f"Demo case created (id {cid}).")
    if creds:
        print("\nDemo accounts (synthetic, shown once — store them safely):")
        for u, p in creds.items():
            print(f"  {u:<13} {p}")


def single_account(_args):
    """Keep one sign-in account: the admin (all permissions). Other accounts are deactivated, not
    deleted, so case history and the audit chain keep their authors. Idempotent."""
    _, c = _conn()
    admins = c.execute("SELECT username FROM users WHERE role='admin' AND active=1 ORDER BY id").fetchall()
    if not admins:
        print("No active admin account; nothing changed.", file=sys.stderr)
        sys.exit(1)
    keep = admins[0]["username"]
    others = [r["username"] for r in c.execute("SELECT username FROM users WHERE active=1 AND username != ?", (keep,))]
    for u in others:
        c.execute("UPDATE users SET active=0 WHERE username=?", (u,))
        audit.record(c, "cli", "user.deactivate", f"user/{u}", {"reason": "single-account mode"})
    c.commit()
    print(json.dumps({"account": keep, "deactivated": others}))


def verify_audit(_args):
    _, c = _conn()
    print(json.dumps(audit.verify_chain(c)))


def main():
    ap = argparse.ArgumentParser(prog="mirqab")
    sub = ap.add_subparsers(required=True)
    p = sub.add_parser("create-user")
    p.add_argument("--username", required=True)
    p.add_argument("--role", choices=["investigator", "reviewer", "admin"], required=True)
    p.add_argument("--display-name")
    p.set_defaults(fn=create_user)
    sub.add_parser("seed-demo").set_defaults(fn=seed_demo)
    sub.add_parser("verify-audit").set_defaults(fn=verify_audit)
    sub.add_parser("single-account").set_defaults(fn=single_account)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
