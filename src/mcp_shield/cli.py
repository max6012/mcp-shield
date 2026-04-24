"""CLI entry point for mcp-shield."""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-shield",
        description="MCP gateway with pattern-based security inspection",
    )
    subparsers = parser.add_subparsers(dest="command")

    # Run the gateway
    run_parser = subparsers.add_parser("run", help="Start the MCP Shield gateway")
    run_parser.add_argument(
        "--config",
        default="mcp-shield.yaml",
        help="Path to gateway config file (default: mcp-shield.yaml)",
    )

    # Audit log queries
    audit_parser = subparsers.add_parser("audit", help="Query the audit log")
    audit_parser.add_argument("--last", type=int, default=50, help="Show last N entries")
    audit_parser.add_argument("--severity", help="Filter by severity")
    audit_parser.add_argument("--tool", help="Filter by tool name")
    audit_parser.add_argument("--db", default="mcp-shield-audit.db", help="Path to audit database")

    args = parser.parse_args()

    if args.command == "run":
        from mcp_shield.gateway import run_gateway

        run_gateway(args.config)
    elif args.command == "audit":
        from mcp_shield.audit import query_audit_log

        query_audit_log(last=args.last, severity=args.severity, tool=args.tool, db_path=args.db)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
