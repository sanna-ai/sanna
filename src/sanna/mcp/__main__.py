"""
Entry point for running Sanna MCP server.

    python -m sanna.mcp
    sanna-mcp
"""

from sanna.mcp.server import run_server


def main() -> None:
    """Run the Sanna MCP server."""
    run_server()


if __name__ == "__main__":
    main()
