"""MCP client for downstream stdio MCP server connections.

Spawns a child process, connects via MCP protocol, discovers tools,
and forwards tool call requests. Part of the sanna-gateway (v0.10.0).
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent

logger = logging.getLogger("sanna.gateway.mcp_client")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DownstreamError(Exception):
    """Base error for downstream MCP connection issues."""


class DownstreamConnectionError(DownstreamError):
    """Failed to connect to or initialize a downstream MCP server."""


class DownstreamTimeoutError(DownstreamError):
    """A downstream MCP operation timed out."""


# ---------------------------------------------------------------------------
# DownstreamConnection
# ---------------------------------------------------------------------------

class DownstreamConnection:
    """MCP client connection to a single downstream stdio MCP server.

    Spawns the server as a child process, performs the MCP handshake,
    discovers available tools, and forwards tool call requests.

    Usage::

        conn = DownstreamConnection(command="python", args=["-m", "my_server"])
        await conn.connect()
        try:
            tools = conn.tools
            result = await conn.call_tool("my_tool", {"arg": "value"})
        finally:
            await conn.close()

    Or as an async context manager::

        async with DownstreamConnection(...) as conn:
            result = await conn.call_tool("my_tool", {"arg": "value"})
    """

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._command = command
        self._args = args or []
        self._env = env
        self._timeout = timeout
        self._session: ClientSession | None = None
        self._tools: list[dict[str, Any]] = []
        self._tool_names: set[str] = set()
        self._exit_stack: AsyncExitStack | None = None
        self._connected = False
        self._last_call_was_connection_error = False

    # -- properties ----------------------------------------------------------

    @property
    def connected(self) -> bool:
        """Whether the client is connected to the downstream server."""
        return self._connected

    @property
    def tools(self) -> list[dict[str, Any]]:
        """Discovered tool schemas from the downstream server."""
        return list(self._tools)

    @property
    def tool_names(self) -> set[str]:
        """Set of discovered tool names."""
        return set(self._tool_names)

    @property
    def last_call_was_connection_error(self) -> bool:
        """Whether the last ``call_tool`` failed due to a connection-level
        error (process crash, timeout, disconnected). Tool-level errors
        (downstream returned ``isError=True``) do NOT set this flag."""
        return self._last_call_was_connection_error

    # -- lifecycle -----------------------------------------------------------

    async def connect(self) -> None:
        """Spawn the downstream server and perform MCP handshake.

        Raises:
            DownstreamConnectionError: If the server cannot be started
                or the MCP handshake fails.
            DownstreamTimeoutError: If connection times out.
        """
        if self._connected:
            raise DownstreamConnectionError("Already connected")

        stack = AsyncExitStack()
        try:
            params = StdioServerParameters(
                command=self._command,
                args=self._args,
                env=self._env,
            )

            read_stream, write_stream = await stack.enter_async_context(
                stdio_client(params)
            )

            session = await stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )

            await asyncio.wait_for(
                session.initialize(), timeout=self._timeout
            )

            tools_result = await asyncio.wait_for(
                session.list_tools(), timeout=self._timeout
            )

            self._tools = [_tool_to_dict(t) for t in tools_result.tools]
            self._tool_names = {t["name"] for t in self._tools}
            self._session = session
            self._exit_stack = stack
            self._connected = True

        except asyncio.TimeoutError:
            await _safe_close_stack(stack)
            raise DownstreamTimeoutError(
                f"Connection to '{self._command}' timed out "
                f"after {self._timeout}s"
            )
        except (FileNotFoundError, OSError) as e:
            await _safe_close_stack(stack)
            raise DownstreamConnectionError(
                f"Failed to start '{self._command}': {e}"
            ) from e
        except DownstreamError:
            await _safe_close_stack(stack)
            raise
        except Exception as e:
            await _safe_close_stack(stack)
            raise DownstreamConnectionError(
                f"Failed to connect to '{self._command}': {e}"
            ) from e

    async def close(self) -> None:
        """Shut down the connection and terminate the child process."""
        self._connected = False
        self._session = None
        self._tools = []
        self._tool_names = set()
        if self._exit_stack is not None:
            await _safe_close_stack(self._exit_stack)
            self._exit_stack = None

    async def reconnect(self) -> None:
        """Close and reconnect to the downstream server.

        Re-discovers tools on success.

        Raises:
            DownstreamConnectionError: If reconnection fails.
            DownstreamTimeoutError: If reconnection times out.
        """
        await self.close()
        await self.connect()

    async def list_tools(self) -> list[dict[str, Any]]:
        """Re-discover tools from the downstream server (protocol-level).

        This is a lightweight MCP protocol call that does not consume
        any user action.  Used by the circuit breaker probe for health
        checks.

        Returns:
            Current tool list from the downstream server.

        Raises:
            DownstreamConnectionError: If not connected or call fails.
            DownstreamTimeoutError: If the operation times out.
        """
        if not self._connected or self._session is None:
            raise DownstreamConnectionError(
                "Not connected to downstream server"
            )

        try:
            tools_result = await asyncio.wait_for(
                self._session.list_tools(), timeout=self._timeout,
            )
            self._tools = [_tool_to_dict(t) for t in tools_result.tools]
            self._tool_names = {t["name"] for t in self._tools}
            return list(self._tools)
        except asyncio.TimeoutError:
            raise DownstreamTimeoutError(
                f"list_tools timed out after {self._timeout}s"
            )
        except Exception as e:
            raise DownstreamConnectionError(
                f"list_tools failed: {type(e).__name__}: {e}"
            ) from e

    # -- tool calls ----------------------------------------------------------

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> CallToolResult:
        """Forward a tool call to the downstream server.

        Returns a ``CallToolResult``.  On success it contains the tool's
        response.  On error (timeout, crash, protocol error) it returns a
        result with ``isError=True`` and a descriptive message.

        Never raises — all errors are captured in the returned result.

        Args:
            name: Tool name.
            arguments: Tool arguments dict.
            timeout: Override the default timeout for this call (seconds).
        """
        if not self._connected or self._session is None:
            self._last_call_was_connection_error = True
            return _error_result("Not connected to downstream server")

        effective_timeout = timeout if timeout is not None else self._timeout

        try:
            result = await asyncio.wait_for(
                self._session.call_tool(name, arguments),
                timeout=effective_timeout,
            )
            self._last_call_was_connection_error = False
            return result

        except asyncio.TimeoutError:
            self._last_call_was_connection_error = True
            return _error_result(
                f"Tool call '{name}' timed out after {effective_timeout}s"
            )
        except Exception as e:
            self._last_call_was_connection_error = True
            self._connected = False
            return _error_result(
                f"Tool call '{name}' failed: {type(e).__name__}: {e}"
            )

    # -- context manager -----------------------------------------------------

    async def __aenter__(self) -> DownstreamConnection:
        await self.connect()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool_to_dict(tool: Any) -> dict[str, Any]:
    """Convert an MCP Tool object to a plain dict preserving all fields."""
    return tool.model_dump(exclude_none=True)


def _error_result(message: str) -> CallToolResult:
    """Create a ``CallToolResult`` representing an error."""
    return CallToolResult(
        content=[TextContent(type="text", text=message)],
        isError=True,
    )


async def _safe_close_stack(stack: AsyncExitStack) -> None:
    """Close an ``AsyncExitStack``, suppressing cleanup errors.

    Catches ``BaseException`` (not just ``Exception``) because
    ``asyncio.CancelledError`` inherits from ``BaseException`` in
    Python 3.9+ and can be raised during process cleanup when
    closing multiple MCP client connections sequentially.
    """
    try:
        await stack.aclose()
    except BaseException:
        logger.debug("Error during stack cleanup", exc_info=True)
