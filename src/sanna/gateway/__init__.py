"""Sanna gateway — MCP enforcement proxy (v0.12.0)."""


def check_mcp_available() -> None:
    """Verify that the ``mcp`` package is installed before gateway startup.

    Called before any MCP imports to give users a clear error message
    when they installed ``pip install sanna`` without the ``[mcp]`` extra.
    """
    import sys

    try:
        import mcp  # noqa: F401
    except ImportError:
        print(
            "Error: The MCP gateway requires the 'mcp' package.\n"
            "Install with: pip install sanna[mcp]\n"
            "You installed 'sanna' without MCP support.",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    """CLI entry point for ``sanna-gateway``.

    Dispatches to:
    - ``migrate`` subcommand: config migration wizard
    - Default (legacy): run the gateway proxy (``--config`` required)
    """
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "migrate":
        from sanna.gateway.migrate import migrate_command

        sys.exit(migrate_command(sys.argv[2:]))
    else:
        check_mcp_available()
        from sanna.gateway.server import run_gateway

        run_gateway()
