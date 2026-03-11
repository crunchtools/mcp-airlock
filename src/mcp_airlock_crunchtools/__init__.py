"""mcp-airlock-crunchtools: Quarantined web content extraction."""

from __future__ import annotations

import argparse

__version__ = "0.2.0"

DEFAULT_PORT = 8019


def main() -> None:
    """Entry point for mcp-airlock-crunchtools."""
    parser = argparse.ArgumentParser(
        prog="mcp-airlock-crunchtools",
        description="MCP server for quarantined web content extraction",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)

    args = parser.parse_args()

    from .database import get_db
    from .server import mcp

    get_db()

    match args.transport:
        case "stdio":
            mcp.run(transport="stdio")
        case "sse":
            mcp.run(transport="sse", host=args.host, port=args.port)
        case _:
            mcp.run(transport="streamable-http", host=args.host, port=args.port)
