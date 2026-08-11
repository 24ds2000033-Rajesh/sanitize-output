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


def response(reason: str):
    return JSONResponse(
        status_code=200,
        content={
            "safe": reason == "SAFE",
            "reason": reason,
        },
    )


# ---------- Patterns ----------

SCRIPT_TAG = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE,
)

EVENT_HANDLER = re.compile(
    r"\bon[a-zA-Z0-9_-]+\s*=",
    re.IGNORECASE,
)

DANGEROUS_SCHEME = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)

SQL_META = re.compile(
    r"""
    '
    |"
    |;
    |--
    |/\*
    |\bunion\b
    |\bor\s+1\s*=\s*1\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SHELL_META = re.compile(
    r"""
    ;
    |&
    |\|
    |`
    |<
    |>
    |\$\(
    |\$\{
    """,
    re.VERBOSE,
)

HTML_URL = re.compile(
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

MARKDOWN_URL = re.compile(
    r"\]\(([^)]*)\)"
)


# ---------- URL extraction ----------

def extract_urls(channel: str, output: str):
    if channel == "html":
        result = []

        for match in HTML_URL.finditer(output):
            value = (
                match.group(1)
                if match.group(1) is not None
                else match.group(2)
            )
            result.append(value)

        return result

    if channel == "markdown":
        return [
            match.group(1).strip()
            for match in MARKDOWN_URL.finditer(output)
        ]

    if channel == "url":
        return [output.strip()]

    return []


# ---------- URL checks ----------

def check_urls(urls):
    for value in urls:
        if not value:
            continue

        value = value.strip()

        # Dangerous schemes explicitly mentioned in the rules.
        if DANGEROUS_SCHEME.search(value):
            return "DANGEROUS_SCHEME"

        # Protocol-relative URLs are absolute and resolve as HTTPS.
        parse_value = value

        if value.startswith("//"):
            parse_value = "https:" + value

        parsed = urlsplit(parse_value)

        # Any explicit scheme must be HTTP or HTTPS.
        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"}:
                return "DANGEROUS_SCHEME"

        # Determine whether this is an absolute URL.
        absolute = (
            value.startswith("//")
            or parsed.scheme.lower() in {"http", "https"}
        )

        # Relative URLs are allowed.
        if not absolute:
            continue

        # Compare parsed hostname only.
        hostname = parsed.hostname

        if hostname not in ALLOWED_HOSTS:
            return "EXTERNAL_EXFIL"

    return None


# ---------- Channel rules ----------

def check_channel(channel: str, output: str):

    if channel == "html":

        if SCRIPT_TAG.search(output):
            return "SCRIPT_TAG"

        if EVENT_HANDLER.search(output):
            return "EVENT_HANDLER"

        if DANGEROUS_SCHEME.search(output):
            return "DANGEROUS_SCHEME"

        reason = check_urls(
            extract_urls("html", output)
        )

        if reason:
            return reason

        return "SAFE"

    if channel == "markdown":

        if DANGEROUS_SCHEME.search(output):
            return "DANGEROUS_SCHEME"

        reason = check_urls(
            extract_urls("markdown", output)
        )

        if reason:
            return reason

        return "SAFE"

    if channel == "url":

        if DANGEROUS_SCHEME.search(output):
            return "DANGEROUS_SCHEME"

        reason = check_urls(
            extract_urls("url", output)
        )

        if reason:
            return reason

        return "SAFE"

    if channel == "sql":

        if SQL_META.search(output):
            return "SQL_METACHAR"

        return "SAFE"

    if channel == "shell":

        if SHELL_META.search(output):
            return "SHELL_METACHAR"

        return "SAFE"

    return "INVALID_SCHEMA"


# ---------- One-time decoding ----------

ENTITY_MAP = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}


def decode_entities(value: str):

    pattern = re.compile(
        r"&(?:#\d+|#x[0-9a-fA-F]+|lt|gt|quot|apos|amp);",
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


def decode_once(value: str):

    # 1. Percent escapes.
    decoded = unquote(value)

    # 2. HTML entities.
    decoded = decode_entities(decoded)

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


# ---------- Endpoint ----------

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # RULE 1: schema
    try:
        body = await request.json()
    except Exception:
        return response("INVALID_SCHEMA")

    if not isinstance(body, dict):
        return response("INVALID_SCHEMA")

    channel = body.get("channel")
    output = body.get("output")

    if channel not in VALID_CHANNELS:
        return response("INVALID_SCHEMA")

    if not isinstance(output, str):
        return response("INVALID_SCHEMA")

    if len(output) > 20000:
        return response("INVALID_SCHEMA")

    # RULE 2: decode once and test decoded output.
    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = check_channel(
            channel,
            decoded,
        )

        if decoded_reason != "SAFE":
            return response("ENCODED_PAYLOAD")

    # RULE 3: test ORIGINAL output.
    reason = check_channel(
        channel,
        output,
    )

    return response(reason)


@app.get("/")
async def health():
    return {"status": "ok"}
