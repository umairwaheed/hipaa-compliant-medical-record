"""Operational CLI. No demo seeding — this only provisions real accounts and
runs compliance checks.

Usage:
    python -m app.cli create-admin --username jdoe --full-name "Jane Doe"
        (password read from HIPAA_ADMIN_PASSWORD env, or prompted)
    python -m app.cli reset-password --username jdoe
    python -m app.cli verify-audit
    python -m app.cli list-users
"""
import argparse
import getpass
import os
import sys

from . import audit as audit_mod
from . import crud, security
from .database import SessionLocal
from .models import User


def _read_password(env_var: str, prompt: str) -> str:
    pw = os.environ.get(env_var)
    if pw:
        return pw
    if not sys.stdin.isatty():
        sys.exit(f"Set {env_var} or run interactively to supply a password.")
    pw = getpass.getpass(prompt)
    confirm = getpass.getpass("Confirm password: ")
    if pw != confirm:
        sys.exit("Passwords do not match.")
    return pw


def create_admin(args) -> None:
    db = SessionLocal()
    try:
        if crud.get_user_by_username(db, args.username):
            sys.exit(f"User '{args.username}' already exists.")
        password = _read_password("HIPAA_ADMIN_PASSWORD", f"Password for {args.username}: ")
        try:
            security.validate_password_policy(password)
        except security.PasswordPolicyError as e:
            sys.exit(f"Password rejected: {e}")
        user = User(
            username=args.username,
            full_name=args.full_name,
            hashed_password=security.hash_password(password),
            role=args.role,
        )
        db.add(user)
        db.commit()
        print(f"Created {args.role} '{args.username}'. MFA must be enrolled at first login.")
    finally:
        db.close()


def reset_password(args) -> None:
    db = SessionLocal()
    try:
        user = crud.get_user_by_username(db, args.username)
        if not user:
            sys.exit(f"No such user '{args.username}'.")
        password = _read_password("HIPAA_NEW_PASSWORD", f"New password for {args.username}: ")
        try:
            security.validate_password_policy(password)
        except security.PasswordPolicyError as e:
            sys.exit(f"Password rejected: {e}")
        user.hashed_password = security.hash_password(password)
        user.token_version += 1  # revoke all existing sessions
        crud.reset_login_failures(db, user)
        db.commit()
        print(f"Password reset for '{args.username}'; existing sessions revoked.")
    finally:
        db.close()


def verify_audit(_args) -> None:
    db = SessionLocal()
    try:
        result = audit_mod.verify_chain(db)
        if result["intact"]:
            print(f"Audit chain INTACT ({result['count']} rows).")
        else:
            sys.exit(f"Audit chain BROKEN at row id {result['broken_at_id']} "
                     f"({result['count']} rows).")
    finally:
        db.close()


def list_users(_args) -> None:
    db = SessionLocal()
    try:
        for u in db.query(User).order_by(User.id).all():
            print(f"{u.id:>3}  {u.username:<20} {u.role:<10} "
                  f"mfa={'on' if u.mfa_enabled else 'off'} active={u.is_active}")
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-admin", help="Create an administrator account")
    p.add_argument("--username", required=True)
    p.add_argument("--full-name", required=True)
    p.add_argument("--role", default="admin", choices=["admin", "clinician"])
    p.set_defaults(func=create_admin)

    p = sub.add_parser("reset-password", help="Reset a user's password")
    p.add_argument("--username", required=True)
    p.set_defaults(func=reset_password)

    p = sub.add_parser("verify-audit", help="Verify the audit hash chain")
    p.set_defaults(func=verify_audit)

    p = sub.add_parser("list-users", help="List user accounts")
    p.set_defaults(func=list_users)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
