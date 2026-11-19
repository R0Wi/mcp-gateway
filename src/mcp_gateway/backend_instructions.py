"""Forward each backend's own server ``instructions`` through the gateway.

fastmcp forwards a proxied backend's instructions only when the proxy is the
root server (``ProxyMetadataMiddleware``). Mounted under the gateway, that
middleware never runs, and the gateway sets its own instructions anyway, so
without this module the guidance a backend ships for its model would be
silently dropped.

Instructions are delivered to a client exactly once, in the gateway's
``initialize`` / ``server/discover`` response, so that response must never
wait on a backend. The text is therefore read by one background task per
backend and the handshake only ever serves what is already cached.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from collections.abc import AsyncIterator, Mapping

from fastmcp import Client
from fastmcp.server.middleware import Middleware
from mcp.types import DiscoverResult

from mcp_gateway.upstream import BackendManager

logger = logging.getLogger(__name__)

# Upper bound on one backend's instruction text. It is appended to every
# client's handshake response and lands in every model's context, so a
# verbose (or compromised) backend must not be able to grow it without limit.
MAX_INSTRUCTIONS_CHARS = 8000
_TRUNCATION_NOTICE = "[Instructions truncated by the gateway]"

# Backend headings are pushed down this many levels so they nest under the
# gateway's own "## Backend `name`" section header instead of sitting beside
# it: no line of backend text can open, close or imitate a backend section.
_HEADING_SHIFT = 2
_MAX_HEADING_LEVEL = 6

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")
_ATX_HEADING = re.compile(r"( {0,3})(#{1,6})(?=[ \t]|$)")
_SETEXT_UNDERLINE = re.compile(r" {0,3}(=+|-+)[ \t]*$")

_PREAMBLE = (
    "Each section below is guidance published by that backend server itself. "
    "It applies only to that backend's tools and refers to them by their "
    "un-prefixed names."
)


def _demote_headings(text: str) -> str:
    """Shift every Markdown heading outside code fences down ``_HEADING_SHIFT`` levels."""
    out: list[str] = []
    fence: str | None = None
    for line in text.split("\n"):
        marker = _FENCE.match(line)
        if marker:
            # A fence closes only on the same character, at least as long.
            run = marker.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence):
                fence = None
            out.append(line)
            continue
        if fence is not None:
            out.append(line)
            continue
        atx = _ATX_HEADING.match(line)
        if atx:
            level = min(len(atx.group(2)) + _HEADING_SHIFT, _MAX_HEADING_LEVEL)
            out.append(f"{atx.group(1)}{'#' * level}{line[atx.end():]}")
            continue
        underline = _SETEXT_UNDERLINE.match(line)
        if underline and out and out[-1].strip() and not _ATX_HEADING.match(out[-1]):
            # Setext heading ("Title" over "====" or "----"): rewrite it as an
            # ATX heading at the demoted level and drop the underline.
            level = (1 if underline.group(1)[0] == "=" else 2) + _HEADING_SHIFT
            out[-1] = f"{'#' * level} {out[-1].strip()}"
            continue
        out.append(line)
    return "\n".join(out)


def sanitize_instructions(text: str | None, *, max_chars: int = MAX_INSTRUCTIONS_CHARS) -> str:
    """Make backend-supplied instruction text safe to splice into the gateway's.

    Caps the length, drops control characters and demotes headings. This
    bounds the size and keeps the section structure intact; it does not (and
    cannot) vet what the text tells a model to do -- an operator who doesn't
    trust a backend's guidance turns it off with ``forward_instructions``.
    """
    if not text:
        return ""
    # Cut first, so no later step ever works on megabytes of input.
    truncated = len(text) > max_chars
    text = text[:max_chars]
    text = _CONTROL_CHARS.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    text = _demote_headings(text).strip()
    if truncated and text:
        text = f"{text}\n\n{_TRUNCATION_NOTICE}"
    return text


def _must_propagate(exc: BaseException) -> bool:
    """Whether `exc` means "this task is being stopped", not "the read failed".

    fastmcp's connect path can surface a ``CancelledError`` (a session task
    that ended cancelled) or a ``BaseExceptionGroup`` without anyone having
    cancelled *this* task; those are just failed reads. A real cancellation
    shows up on the task itself.
    """
    task = asyncio.current_task()
    if task is not None and task.cancelling():
        return True
    fatal = (KeyboardInterrupt, SystemExit, GeneratorExit)
    if isinstance(exc, BaseExceptionGroup):
        return exc.subgroup(fatal) is not None
    return isinstance(exc, fatal)


class BackendInstructionsMiddleware(Middleware):
    """Append every backend's own server ``instructions`` to the gateway's.

    Each backend's text goes in its own section, headed by the namespace its
    tools were mounted under, since the text refers to the backend's
    un-prefixed tool names. Works for both protocol eras: ``initialize``
    (handshake) and ``server/discover`` (sessionless ``2026-07-28``).

    ``refreshing()`` runs one task per backend that re-reads the text every
    ``ttl`` seconds, or after ``failure_ttl`` when the read failed. A failed
    read keeps the last value that was read successfully. The handshake does
    no network I/O: it serves the cache, so a slow, hung or down backend costs
    other clients nothing. The one exception is the first ``startup_grace``
    seconds after start, during which a handshake waits for the initial reads
    to land (and never past that mark), so clients that reconnect the moment
    the gateway comes back still get the text.

    Reads are never cancelled on a timer. They are bounded by the transport's
    own HTTP timeouts instead: a read on an OAuth backend can include a
    refresh-token grant, and cancelling one between the request and the
    response being stored would lose a rotated refresh token.
    """

    def __init__(
        self,
        clients: Mapping[str, Client],
        manager: BackendManager,
        *,
        ttl: float = 300.0,
        failure_ttl: float = 30.0,
        startup_grace: float = 3.0,
        max_chars: int = MAX_INSTRUCTIONS_CHARS,
    ) -> None:
        self._clients = dict(clients)
        self._manager = manager
        self._ttl = ttl
        self._failure_ttl = failure_ttl
        self._startup_grace = startup_grace
        self._max_chars = max_chars
        # name -> sanitized, non-empty instruction text
        self._cache: dict[str, str] = {}
        # Set once every backend's first read has finished (or failed); only
        # exists while refreshing() is active.
        self._warm: asyncio.Event | None = None
        self._warm_deadline = 0.0

    @contextlib.asynccontextmanager
    async def refreshing(self) -> AsyncIterator[None]:
        """Keep the cache fresh for as long as the context is open."""
        # Startup bookkeeping belongs to this run alone: the tasks get their
        # own references, so a task from an earlier run that is still
        # unwinding can never mark a later run as warm.
        awaiting_first_read = set(self._clients)
        warm = asyncio.Event()
        self._warm = warm
        self._warm_deadline = time.monotonic() + self._startup_grace
        tasks = [
            asyncio.create_task(
                self._refresh_loop(name, client, awaiting_first_read, warm),
                name=f"instructions-{name}",
            )
            for name, client in self._clients.items()
        ]
        if not tasks:
            warm.set()
        try:
            yield
        finally:
            # Reset before awaiting anything: the await below raises
            # CancelledError if whoever is closing this context is cancelled
            # meanwhile (shutdown is not guaranteed to run undisturbed), and
            # any line after it would then be skipped.
            if self._warm is warm:
                self._warm = None
            for task in tasks:
                task.cancel()
            # Child failures are returned, not raised; this only raises if
            # this task is cancelled, and the children are already cancelled.
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _refresh_loop(
        self, name: str, client: Client, awaiting_first_read: set[str], warm: asyncio.Event
    ) -> None:
        while True:
            try:
                ok = await self._refresh(name, client)
            except BaseException as exc:
                if _must_propagate(exc):
                    raise
                # One backend must never take down its own refresh loop, let
                # alone anything else; keep whatever is cached and retry.
                logger.debug(
                    "Backend %s: could not read server instructions: %s: %s",
                    name,
                    type(exc).__name__,
                    exc,
                )
                ok = False
            awaiting_first_read.discard(name)
            if not awaiting_first_read:
                warm.set()
            await asyncio.sleep(self._ttl if ok else self._failure_ttl)

    async def _refresh(self, name: str, client: Client) -> bool:
        """Read one backend's instructions into the cache; False means retry soon."""
        if not self._manager.is_connected(name):
            # An OAuth backend nobody has connected (or that was disconnected
            # on purpose) exposes no tools, so it gets no section either. Not
            # contacting it also keeps this task out of the OAuth machinery.
            self._store(name, "")
            return False
        if self._manager.connect_in_progress(name):
            # An admin is authorizing this backend right now and that flow
            # holds the backend's OAuth provider; stay out of its way.
            return False
        # A separate client instance: never touch the proxy's own sessions.
        # This runs outside any inbound request, so there are no caller
        # headers in scope to forward in the first place.
        async with client.new() as fresh:
            text = fresh.instructions
        self._store(name, sanitize_instructions(text, max_chars=self._max_chars))
        return True

    def _store(self, name: str, text: str) -> None:
        if text == self._cache.get(name, ""):
            return
        if text:
            self._cache[name] = text
            logger.info("Backend %s: forwarding its server instructions (%d chars)", name, len(text))
        else:
            del self._cache[name]
            logger.info("Backend %s: no longer forwarding server instructions", name)

    async def _wait_for_initial_reads(self) -> None:
        warm = self._warm
        if warm is None or warm.is_set():
            return
        remaining = self._warm_deadline - time.monotonic()
        if remaining > 0:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(warm.wait(), timeout=remaining)

    async def merged(self, base: str | None) -> str | None:
        """`base` (the gateway's own instructions) plus one section per backend."""
        await self._wait_for_initial_reads()
        sections = [
            f"## Backend `{name}` (its tools are exposed with the prefix `{name}_`)\n\n{text}"
            for name in self._clients
            if (text := self._cache.get(name))
        ]
        if not sections:
            return base
        return "\n\n".join([*([base] if base else []), _PREAMBLE, *sections])

    async def _with_backend_instructions(self, result):
        return result.model_copy(update={"instructions": await self.merged(result.instructions)})

    async def on_initialize(self, context, call_next):
        result = await call_next(context)
        if result is None:
            return None
        return await self._with_backend_instructions(result)

    async def on_discover(self, context, call_next):
        result = await call_next(context)
        if not isinstance(result, DiscoverResult):
            return result
        return await self._with_backend_instructions(result)
