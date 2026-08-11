import json
import re
from urllib.parse import unquote, urlsplit

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
# Response
# ---------------------------------------------------------

def make_response(reason: str):
    return JSONResponse(
        status_code=200,
        content={
            "safe": reason == "SAFE",
            "reason": reason,
        },
    )


# ---------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------

SCRIPT_TAG_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE,
)

EVENT_HANDLER_RE = re.compile(
    r"\bon[a-zA-Z0-9_-]+\s*=",
    re.IGNORECASE,
)

DANGEROUS_SCHEME_RE = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)

SQL_METACHAR_RE = re.compile(
    r"""
    '
    |
    "
    |
    ;
    |
    --
    |
    /\*
    |
    \bunion\b
    |
    \bor\s+1\s*=\s*1\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SHELL_METACHAR_RE = re.compile(
    r"""
    ;
    |
    &
    |
    \|
    |
    `
    |
    <
    |
    >
    |
    \$\(
    |
    \$\{
    """,
    re.VERBOSE,
)

HTML_URL_RE = re.compile(
    r"""
    \b(?:src|href)
    \s*=\s*
    (?:
        "([^"]*)"
        |
        '([^']*)'
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

MARKDOWN_URL_RE = re.compile(
    r"\]\(([^)]*)\)",
    re.VERBOSE,
)


# ---------------------------------------------------------
# URL extraction
# ---------------------------------------------------------

def extract_urls(channel: str, output: str):
    if channel == "html":
        urls = []

        for match in HTML_URL_RE.finditer(output):
            value = (
                match.group(1)
                if match.group(1) is not None
                else match.group(2)
            )
            urls.append(value)

        return urls

    if channel == "markdown":
        return [
            match.group(1).strip()
            for match in MARKDOWN_URL_RE.finditer(output)
        ]

    if channel == "url":
        return [output.strip()]

    return []


# ---------------------------------------------------------
# URL checks
# ---------------------------------------------------------

def check_urls(urls):
    for value in urls:
        if not value:
            continue

        value = value.strip()

        # Explicit dangerous schemes.
        if DANGEROUS_SCHEME_RE.search(value):
            return "DANGEROUS_SCHEME"

        # Protocol-relative URLs are absolute and resolve as HTTPS.
        parse_value = value

        if value.startswith("//"):
            parse_value = "https:" + value

        parsed = urlsplit(parse_value)

        # If a scheme is present, only HTTP/HTTPS are allowed.
        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"}:
                return "DANGEROUS_SCHEME"

        # Absolute URL means:
        #   http://...
        #   https://...
        #   //host/...
        absolute = (
            value.startswith("//")
            or parsed.scheme.lower() in {"http", "https"}
        )

        if not absolute:
            continue

        hostname = parsed.hostname

        # Exact hostname comparison.
        if hostname not in ALLOWED_HOSTS:
            return "EXTERNAL_EXFIL"

    return None


# ---------------------------------------------------------
# Channel checks
# ---------------------------------------------------------

def check_channel(channel, output):
    if channel == "html":
        if SCRIPT_TAG_RE.search(output):
            return "SCRIPT_TAG"

        if EVENT_HANDLER_RE.search(output):
            return "EVENT_HANDLER"

        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        reason = check_urls(extract_urls(channel, output))

        if reason:
            return reason

        return "SAFE"

    if channel == "markdown":
        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        reason = check_urls(extract_urls(channel, output))

        if reason:
            return reason

        return "SAFE"

    if channel == "url":
        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        reason = check_urls(extract_urls(channel, output))

        if reason:
            return reason

        return "SAFE"

    if channel == "sql":
        if SQL_METACHAR_RE.search(output):
            return "SQL_METACHAR"

        return "SAFE"

    if channel == "shell":
        if SHELL_METACHAR_RE.search(output):
            return "SHELL_METACHAR"

        return "SAFE"

    return "INVALID_SCHEMA"


# ---------------------------------------------------------
# Decode exactly once
# ---------------------------------------------------------

ENTITY_MAP = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}


def decode_html_entities_once(value):
    pattern = re.compile(
        r"&(?:#[0-9]+|#x[0-9a-fA-F]+|lt|gt|quot|apos|amp);",
        re.IGNORECASE,
    )

    def replace(match):
        token = match.group(0)

        lower = token.lower()

        if lower in ENTITY_MAP:
            return ENTITY_MAP[lower]

        if lower.startswith("&#x"):
            try:
                return chr(int(token[3:-1], 16))
            except (ValueError, OverflowError):
                return token

        if lower.startswith("&#"):
            try:
                return chr(int(token[2:-1], 10))
            except (ValueError, OverflowError):
                return token

        return token

    return pattern.sub(replace, value)


def decode_once(value):
    # 1. Percent escapes.
    decoded = unquote(value)

    # 2. HTML entities.
    decoded = decode_html_entities_once(decoded)

    # 3. \uXXXX escapes.
    def replace_unicode(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        replace_unicode,
        decoded,
    )

    return decoded


# ---------------------------------------------------------
# Endpoint
# ---------------------------------------------------------

@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    # Rule 1: JSON/body validation.
    try:
        body = await request.json()
    except Exception:
        return make_response("INVALID_SCHEMA")

    if not isinstance(body, dict):
        return make_response("INVALID_SCHEMA")

    channel = body.get("channel")
    output = body.get("output")

    if channel not in VALID_CHANNELS:
        return make_response("INVALID_SCHEMA")

    if not isinstance(output, str):
        return make_response("INVALID_SCHEMA")

    if len(output) > 20000:
        return make_response("INVALID_SCHEMA")

    # Rule 2: decode once.
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = check_channel(channel, decoded)

        if decoded_reason != "SAFE":
            return make_response("ENCODED_PAYLOAD")

    # Rule 3: evaluate ORIGINAL output.
    reason = check_channel(channel, output)

    return make_response(reason)


@app.get("/")
async def health():
    return {"status": "ok"}
