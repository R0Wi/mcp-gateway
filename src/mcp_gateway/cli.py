"""Command-line entry point: `mcp-gateway run` / `mcp-gateway hash-password`."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-gateway", description="Self-hosted MCP gateway")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run the gateway server")
    run.add_argument(
        "-c",
        "--config",
        default=os.environ.get("MCP_GATEWAY_CONFIG", "config.yaml"),
        help="Path to the YAML config file (default: config.yaml or $MCP_GATEWAY_CONFIG)",
    )
    run.add_argument("--log-level", default="info")

    sub.add_parser("hash-password", help="Generate a bcrypt hash for the users section")

    check = sub.add_parser("check", help="Validate the config file and exit")
    check.add_argument(
        "-c",
        "--config",
        default=os.environ.get("MCP_GATEWAY_CONFIG", "config.yaml"),
    )

    args = parser.parse_args(argv)

    if args.command == "hash-password":
        import bcrypt

        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm: ")
        if password != confirm:
            print("Passwords do not match", file=sys.stderr)
            return 1
        print(bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode())
        return 0

    from mcp_gateway.config import load_config

    if args.command == "check":
        config = load_config(args.config)
        print(f"OK: {len(config.auth.users)} user(s), {len(config.backends)} backend(s)")
        return 0

    if args.command == "run":
        import uvicorn

        from mcp_gateway.app import create_app

        logging.basicConfig(
            level=getattr(logging, args.log_level.upper(), logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        config = load_config(args.config)
        app = create_app(config)
        uvicorn.run(
            app,
            host=config.server.host,
            port=config.server.port,
            log_level=args.log_level,
            # The gateway sits behind a reverse proxy that terminates TLS.
            proxy_headers=True,
            forwarded_allow_ips="*",
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
