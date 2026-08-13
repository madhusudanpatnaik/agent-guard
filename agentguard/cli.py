"""Command-line entrypoint: ``agentguard serve|seed|verify``."""

from __future__ import annotations

import argparse
import sys


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .config import get_settings

    settings = get_settings()
    uvicorn.run(
        "agentguard.main:app",
        host=args.host or settings.host,
        port=args.port or settings.port,
        reload=args.reload,
    )
    return 0


def _proxy(args: argparse.Namespace) -> int:
    from .config import get_settings
    from .database import init_db
    from .logging_config import configure_logging
    from .proxy import serve_proxy

    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    init_db()
    try:
        serve_proxy(args.host or settings.host, args.port)
    except KeyboardInterrupt:
        pass
    return 0


def _seed(args: argparse.Namespace) -> int:
    from .seeds import seed

    keys = seed(reset=args.reset)
    if keys:
        print("Created agents (store these API keys securely — shown once):")
        for name, key in keys.items():
            print(f"  {name:18} {key}")
    else:
        print("No new agents created (already seeded).")
    return 0


def _verify(args: argparse.Namespace) -> int:
    from .audit.ledger import verify_chain
    from .database import SessionLocal, init_db

    init_db()
    with SessionLocal() as db:
        status = verify_chain(db)
    print(status.as_dict())
    return 0 if status.valid else 1


def _rotate_vault_key(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from .config import get_settings
    from .database import SessionLocal, init_db
    from .models import Connector
    from .vault import reencrypt_secret

    old_key = get_settings().effective_vault_key()
    new_key = args.new_key
    if not new_key:
        print("error: --new-key is required")
        return 2
    if new_key == old_key:
        print("error: new key equals the current key; nothing to do")
        return 2

    init_db()
    rotated = 0
    with SessionLocal() as db:
        for c in db.scalars(select(Connector)):
            if c.auth_secret_encrypted:
                c.auth_secret_encrypted = reencrypt_secret(
                    c.auth_secret_encrypted, old_key, new_key
                )
                rotated += 1
        db.commit()
    print(f"Re-encrypted {rotated} connector secret(s) under the new key.")
    print("Now set AGENTGUARD_VAULT_KEY to the new value and restart the service.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard", description="AgentGuard control plane")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the API + console server")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=_serve)

    proxy = sub.add_parser(
        "proxy", help="Run the transparent forward proxy (govern agents with no SDK)")
    proxy.add_argument("--host", default=None)
    proxy.add_argument("--port", type=int, default=8888)
    proxy.set_defaults(func=_proxy)

    seed = sub.add_parser("seed", help="Populate demo roles, policies and agents")
    seed.add_argument("--reset", action="store_true", help="Drop existing data first")
    seed.set_defaults(func=_seed)

    verify = sub.add_parser("verify", help="Verify audit-ledger integrity")
    verify.set_defaults(func=_verify)

    rotate = sub.add_parser(
        "rotate-vault-key", help="Re-encrypt connector secrets under a new vault key"
    )
    rotate.add_argument("--new-key", required=True, help="The new AGENTGUARD_VAULT_KEY value")
    rotate.set_defaults(func=_rotate_vault_key)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
