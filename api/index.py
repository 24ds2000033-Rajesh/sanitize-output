import html
import json
import re
from urllib.parse import urlsplit, unquote

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

def result(reason: str) -> JSONResponse:
    return JSONResponse(
        content={
            "safe": reason == "SAFE",
            "reason": reason,
        }
    )


# ---------------------------------------------------------
# Rule detection
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
    '                       # single quote
    | "                     # double quote
    | ;                     # semicolon
    | --                    # SQL comment
    | /\*                   # block comment start
    | \bunion\b             # union
    | \bor\s+1\s*=\s*1\b    # or 1=1
    """,
    re.IGNORECASE | re.VERBOSE,
)

SHELL_METACHAR_RE = re.compile(
    r"""
    ;
    | &
    | \|
    | `
    | <
    | >
    | \$\(
    | \$\{
    """,
    re.VERBOSE,
)


# ---------------------------------------------------------
# URL extraction
# ---------------------------------------------------------

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
    r"""
    \]\(
        ([^)]*)
    \)
    """,
    re.VERBOSE,
)


def extract_urls(channel: str, output: str) -> list[str]:
    if channel == "html":
        urls = []
        for match in HTML_URL_RE.finditer(output):
            urls.append(match.group(1) if match.group(1) is not None else match.group(2))
        return urls

    if channel == "markdown":
        return [m.group(1).strip() for m in MARKDOWN_URL_RE.finditer(output)]

    if channel == "url":
        return [output.strip()]

    return []


# ---------------------------------------------------------
# URL safety
# ---------------------------------------------------------

def url_rule_reason(urls: list[str]) -> str | None:
    for raw_url in urls:
        if not raw_url:
            continue

        value = raw_url.strip()

        # Browser treats //host/path as an absolute URL.
        parsed_value = value

        if value.startswith("//"):
            parsed_value = "https:" + value

        parsed = urlsplit(parsed_value)

        # Explicit dangerous schemes anywhere in the URL.
        if DANGEROUS_SCHEME_RE.search(value):
            return "DANGEROUS_SCHEME"

        # If an extracted URL has a scheme, only HTTP/HTTPS are allowed.
        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"}:
                return "DANGEROUS_SCHEME"

        # Absolute URL:
        #   http://...
        #   https://...
        #   //host/...
        is_absolute = (
            value.startswith("//")
            or parsed.scheme.lower() in {"http", "https"}
        )

        if is_absolute:
            hostname = parsed.hostname

            # Hostname comparison is exact.
            if hostname not in ALLOWED_HOSTS:
                return "EXTERNAL_EXFIL"

    return None


# ---------------------------------------------------------
# Channel-specific checks
# ---------------------------------------------------------

def check_channel(channel: str, output: str) -> str:
    if channel == "html":
        # 1. SCRIPT_TAG
        if SCRIPT_TAG_RE.search(output):
            return "SCRIPT_TAG"

        # 2. EVENT_HANDLER
        if EVENT_HANDLER_RE.search(output):
            return "EVENT_HANDLER"

        # 3 + 4. URL-related checks
        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)
        reason = url_rule_reason(urls)

        if reason:
            return reason

        return "SAFE"

    if channel == "markdown":
        # DANGEROUS_SCHEME first.
        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)
        reason = url_rule_reason(urls)

        if reason:
            return reason

        return "SAFE"

    if channel == "url":
        # DANGEROUS_SCHEME first.
        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        urls = extract_urls(channel, output)
        reason = url_rule_reason(urls)

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

    # Should never be reached after schema validation.
    return "INVALID_SCHEMA"


# ---------------------------------------------------------
# Decode exactly once
# ---------------------------------------------------------

def decode_once(value: str) -> str:
    """
    Decode in the required order:

    1. percent escapes
    2. HTML entities
    3. \\uXXXX escapes
    """

    # 1. Percent decoding
    decoded = unquote(value)

    # 2. Only the specified HTML entities are decoded.
    # html.unescape also handles other named entities, so restrict
    # decoding to the entities explicitly specified by the challenge.
    entity_map = {
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&apos;": "'",
        "&amp;": "&",
    }

    def replace_entity(match):
        token = match.group(0)

        # Numeric decimal: &#NN;
        if re.fullmatch(r"&#[0-9]+;", token):
            try:
                return chr(int(token[2:-1], 10))
            except (ValueError, OverflowError):
                return token

        # Numeric hexadecimal: &#xNN;
        if re.fullmatch(r"&#x[0-9a-fA-F]+;", token):
            try:
                return chr(int(token[3:-1], 16))
            except (ValueError, OverflowError):
                return token

        return entity_map.get(token.lower(), token)

    decoded = re.sub(
        r"&(?:#\d+|#x[0-9a-fA-F]+|lt|gt|quot|apos|amp);",
        replace_entity,
        decoded,
        flags=re.IGNORECASE,
    )

    # 3. Decode literal \uXXXX escapes once.
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
# Main endpoint
# ---------------------------------------------------------

@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    # Do our own JSON parsing so malformed/non-object bodies also
    # receive the required response shape.
    try:
        body = await request.json()
    except Exception:
        return result("INVALID_SCHEMA")

    # Rule 1: body must be an object.
    # bool is technically an int in Python, so explicitly reject it.
    if not isinstance(body, dict):
        return result("INVALID_SCHEMA")

    channel = body.get("channel")
    output = body.get("output")

    if channel not in VALID_CHANNELS:
        return result("INVALID_SCHEMA")

    if not isinstance(output, str):
        return result("INVALID_SCHEMA")

    if len(output) > 20000:
        return result("INVALID_SCHEMA")

    # Rule 2: decode exactly once.
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = check_channel(channel, decoded)

        if decoded_reason != "SAFE":
            return result("ENCODED_PAYLOAD")

    # Rule 3: check ORIGINAL output.
    reason = check_channel(channel, output)

    return result(reason)


# Optional health endpoint for easy testing.
@app.get("/")
async def root():
    return {"status": "ok"}
