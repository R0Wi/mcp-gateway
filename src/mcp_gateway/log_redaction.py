"""Keep credentials embedded in URLs out of the logs.

Operators sometimes authenticate to a backend with a secret in the URL itself
(``https://host/mcp?api_key=...``). Both the gateway's own log lines and the
HTTP client's per-request INFO line would otherwise write that URL verbatim.

Deliberately stdlib-only: ``mcp_gateway/__init__.py`` imports this while
configuring logging, before anything else (FastMCP in particular) is imported,
which is why this lives apart from ``diagnostics`` (that one imports httpx2 and
the MCP SDK).
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit, urlunsplit

# A URL inside free-form log text. Stops at whitespace and at the quote and
# bracket characters log formats commonly wrap a URL in.
_URL_RE = re.compile(r"""[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>()\[\]]+""")


def _strip_query(text: str) -> str:
    """``text`` (a URL) without its query string and fragment. Never raises."""
    try:
        parts = urlsplit(text)
    except ValueError:
        return re.split(r"[?#]", text, maxsplit=1)[0]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def strip_queries_in_text(text: str) -> str:
    """Remove the query string and fragment from every URL found in ``text``."""
    return _URL_RE.sub(lambda m: _strip_query(m.group(0)), text)


class StripUrlQueryFilter(logging.Filter):
    """Logging filter that removes query strings from URLs in a record's message.

    The message is rendered once and the record's ``args`` cleared, so the URL
    is redacted for every handler, whatever its formatter.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - leave a malformed record to the handler
            return True
        redacted = strip_queries_in_text(message)
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True


# Loggers of the HTTP client libraries, which log every request URL at INFO.
# FastMCP and the MCP SDK use httpx2; plain httpx is covered in case anything
# else in the process (or a future dependency) uses it.
HTTP_CLIENT_LOGGERS = ("httpx2", "httpx")


def install_url_query_filters() -> None:
    """Attach :class:`StripUrlQueryFilter` to the HTTP client loggers (idempotent)."""
    for name in HTTP_CLIENT_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(f, StripUrlQueryFilter) for f in logger.filters):
            logger.addFilter(StripUrlQueryFilter())
