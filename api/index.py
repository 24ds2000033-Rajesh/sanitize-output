import html
import json
import re
from typing import Any
from urllib.parse import unquote, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-xhol1me.example",
    "app-3ngcuo6.example",
}

VALID_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


# ---------------------------------------------------------
# Response helper
# ---------------------------------------------------------

def decision(safe: bool, reason: str) -> JSONResponse:
    return JSONResponse(
        content={
            "safe": safe,
            "reason": reason,
        }
    )


# ---------------------------------------------------------
# Schema validation
# ---------------------------------------------------------

async def read_valid_body(request: Request):
    try:
        body = await request.json()
    except Exception:
        return None

    if not isinstance(body, dict):
        return None

    if body.get("channel") not in VALID_CHANNELS:
        return None

    output = body.get("output")

    if not isinstance(output, str):
        return None

    if len(output) > 20000:
        return None

    return body


# ---------------------------------------------------------
# One-time decoding
#
# Order:
#   1. percent escapes
#   2. selected HTML entities
#   3. \uXXXX escapes
# ---------------------------------------------------------

NAMED_ENTITIES = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}

HTML_ENTITY_RE = re.compile(
    r"&#(?:[0-9]+|[xX][0-9A-Fa-f]+);|&(?:lt|gt|quot|apos|amp);"
)

UNICODE_ESCAPE_RE = re.compile(
    r"\\u([0-9A-Fa-f]{4})"
)


def decode_once(value: str) -> str:
    # 1. Percent decoding
    decoded = unquote(value)

    # 2. Only the explicitly specified HTML entities
    def replace_entity(match: re.Match) -> str:
        token = match.group(0)

        if token in NAMED_ENTITIES:
            return NAMED_ENTITIES[token]

        if token.startswith("&#x") or token.startswith("&#X"):
            try:
                return chr(int(token[3:-1], 16))
            except ValueError:
                return token

        if token.startswith("&#"):
            try:
                return chr(int(token[2:-1], 10))
            except ValueError:
                return token

        return token

    decoded = HTML_ENTITY_RE.sub(replace_entity, decoded)

    # 3. \uXXXX
    def replace_unicode(match: re.Match) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    decoded = UNICODE_ESCAPE_RE.sub(replace_unicode, decoded)

    return decoded


# ---------------------------------------------------------
# Generic dangerous scheme detection
# ---------------------------------------------------------

DANGEROUS_SCHEME_RE = re.compile(
    r"(?i)\b(?:javascript|data|vbscript)\s*:"
)


def has_dangerous_scheme_text(text: str) -> bool:
    return bool(DANGEROUS_SCHEME_RE.search(text))


# ---------------------------------------------------------
# URL extraction
# ---------------------------------------------------------

# HTML quoted src/href attributes only.
HTML_URL_RE = re.compile(
    r"""(?is)\b(?:src|href)\s*=\s*(['"])(.*?)\1"""
)

# Markdown link target: ](...)
MARKDOWN_URL_RE = re.compile(
    r"""\]\(([^)]*)\)""",
    re.DOTALL,
)


def extract_urls(channel: str, output: str) -> list[str]:
    if channel == "html":
        return [
            match.group(2).strip()
            for match in HTML_URL_RE.finditer(output)
        ]

    if channel == "markdown":
        urls = []

        for match in MARKDOWN_URL_RE.finditer(output):
            target = match.group(1).strip()

            # Markdown may contain an optional title after the URL.
            # We only need the URL portion for scheme/hostname checks.
            if target.startswith("<"):
                end = target.find(">")
                if end != -1:
                    urls.append(target[1:end].strip())
                    continue

            # Split on whitespace for the common:
            # ](https://host/path "title")
            urls.append(target.split()[0] if target else "")

        return urls

    if channel == "url":
        value = output.strip()
        return [value] if value else []

    return []


# ---------------------------------------------------------
# URL safety
# ---------------------------------------------------------

def url_has_dangerous_scheme(url: str) -> bool:
    """
    Returns True when:
      - javascript:, data:, vbscript: appears
      - an extracted URL has a scheme other than http/https
    """

    if has_dangerous_scheme_text(url):
        return True

    value = url.strip()

    # Protocol-relative URL is allowed to proceed to hostname checking.
    if value.startswith("//"):
        return False

    parsed = urlparse(value)

    if parsed.scheme:
        return parsed.scheme.lower() not in {"http", "https"}

    # Relative URL is fine.
    return False


def is_external_exfil(url: str) -> bool:
    """
    Absolute URLs and protocol-relative URLs must point to exactly
    one of the two allowed hostnames.

    Hostname is compared only, so:
      allowed.example.evil
      evil@allowed.example
      allowed.example.evil/path

    do not bypass the check.
    """

    value = url.strip()

    if not value:
        return False

    # Protocol-relative references are absolute for this policy.
    if value.startswith("//"):
        parsed = urlparse("https:" + value)
    else:
        parsed = urlparse(value)

    # Relative reference.
    if not parsed.scheme:
        return False

    # Only http/https should reach this point.
    if parsed.scheme.lower() not in {"http", "https"}:
        return True

    hostname = parsed.hostname

    if hostname is None:
        return True

    return hostname.lower() not in ALLOWED_HOSTS


def check_urls(channel: str, output: str) -> str | None:
    """
    Returns the first matching reason:
      DANGEROUS_SCHEME
      EXTERNAL_EXFIL
      None
    """

    # First inspect dangerous scheme text.
    if has_dangerous_scheme_text(output):
        return "DANGEROUS_SCHEME"

    urls = extract_urls(channel, output)

    # Then inspect extracted URL schemes.
    for url in urls:
        if url_has_dangerous_scheme(url):
            return "DANGEROUS_SCHEME"

    # Then inspect external hosts.
    for url in urls:
        if is_external_exfil(url):
            return "EXTERNAL_EXFIL"

    return None


# ---------------------------------------------------------
# HTML rules
# ---------------------------------------------------------

SCRIPT_TAG_RE = re.compile(
    r"""(?is)<\s*(?:script|iframe|object|embed)\b"""
)

EVENT_HANDLER_RE = re.compile(
    r"""(?is)\bon[a-zA-Z0-9_-]+\s*="""
)


def check_html(output: str) -> str | None:
    if SCRIPT_TAG_RE.search(output):
        return "SCRIPT_TAG"

    if EVENT_HANDLER_RE.search(output):
        return "EVENT_HANDLER"

    return check_urls("html", output)


# ---------------------------------------------------------
# SQL rules
# ---------------------------------------------------------

SQL_META_RE = re.compile(
    r"""(?is)(?:'|"|;|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b)"""
)


def check_sql(output: str) -> str | None:
    if SQL_META_RE.search(output):
        return "SQL_METACHAR"

    return None


# ---------------------------------------------------------
# Shell rules
# ---------------------------------------------------------

SHELL_META_RE = re.compile(
    r"""[;&|`<>]|\$\(|\$\{"""
)


def check_shell(output: str) -> str | None:
    if SHELL_META_RE.search(output):
        return "SHELL_METACHAR"

    return None


# ---------------------------------------------------------
# Channel dispatcher
# ---------------------------------------------------------

def check_original(channel: str, output: str) -> str | None:
    if channel == "html":
        return check_html(output)

    if channel == "markdown":
        return check_urls("markdown", output)

    if channel == "url":
        return check_urls("url", output)

    if channel == "sql":
        return check_sql(output)

    if channel == "shell":
        return check_shell(output)

    return "INVALID_SCHEMA"


# ---------------------------------------------------------
# Endpoint
# ---------------------------------------------------------

@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    body = await read_valid_body(request)

    # Rule 1
    if body is None:
        return decision(False, "INVALID_SCHEMA")

    channel = body["channel"]
    output = body["output"]

    # Rule 2:
    # Decode exactly once. If the decoded representation differs and
    # the decoded value would fail any channel rule, return
    # ENCODED_PAYLOAD before checking the original.
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = check_original(channel, decoded)

        if decoded_reason is not None:
            return decision(False, "ENCODED_PAYLOAD")

    # Rule 3:
    reason = check_original(channel, output)

    if reason is not None:
        return decision(False, reason)

    return decision(True, "SAFE")
