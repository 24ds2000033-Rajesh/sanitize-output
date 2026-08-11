import json
import re
from http.server import BaseHTTPRequestHandler
from urllib.parse import unquote, urlsplit


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
# Patterns
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
    r"\]\(([^)]*)\)"
)


# ---------------------------------------------------------
# Response
# ---------------------------------------------------------

def make_result(reason):
    return {
        "safe": reason == "SAFE",
        "reason": reason,
    }


# ---------------------------------------------------------
# URL extraction
# ---------------------------------------------------------

def extract_urls(channel, output):

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

        # Protocol-relative URL is absolute and resolves as HTTPS.
        parse_value = value

        if value.startswith("//"):
            parse_value = "https:" + value

        parsed = urlsplit(parse_value)

        # Any extracted URL with a scheme must use HTTP/HTTPS.
        if parsed.scheme:
            if parsed.scheme.lower() not in {"http", "https"}:
                return "DANGEROUS_SCHEME"

        # Absolute URL:
        #   http://...
        #   https://...
        #   //host/...
        absolute = (
            value.startswith("//")
            or parsed.scheme.lower() in {"http", "https"}
        )

        # Relative references are allowed.
        if not absolute:
            continue

        # Compare parsed hostname ONLY.
        hostname = parsed.hostname

        if hostname not in ALLOWED_HOSTS:
            return "EXTERNAL_EXFIL"

    return None


# ---------------------------------------------------------
# Channel checks
# ---------------------------------------------------------

def check_channel(channel, output):

    if channel == "html":

        # 1. SCRIPT_TAG
        if SCRIPT_TAG_RE.search(output):
            return "SCRIPT_TAG"

        # 2. EVENT_HANDLER
        if EVENT_HANDLER_RE.search(output):
            return "EVENT_HANDLER"

        # 3. DANGEROUS_SCHEME
        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        # 4. EXTERNAL_EXFIL
        reason = check_urls(
            extract_urls("html", output)
        )

        if reason:
            return reason

        return "SAFE"

    if channel == "markdown":

        # 1. DANGEROUS_SCHEME
        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        # 2. EXTERNAL_EXFIL
        reason = check_urls(
            extract_urls("markdown", output)
        )

        if reason:
            return reason

        return "SAFE"

    if channel == "url":

        # 1. DANGEROUS_SCHEME
        if DANGEROUS_SCHEME_RE.search(output):
            return "DANGEROUS_SCHEME"

        # 2. EXTERNAL_EXFIL
        reason = check_urls(
            extract_urls("url", output)
        )

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
# One-time decoding
# ---------------------------------------------------------

NAMED_ENTITIES = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}


HTML_ENTITY_RE = re.compile(
    r"&(?:#[0-9]+|#x[0-9A-Fa-f]+|lt|gt|quot|apos|amp);"
)


def decode_html_entities(value):

    def replace(match):

        token = match.group(0)

        # Specified named entities.
        if token in NAMED_ENTITIES:
            return NAMED_ENTITIES[token]

        # Decimal numeric entity.
        if token.startswith("&#") and not token.startswith("&#x"):
            try:
                return chr(int(token[2:-1], 10))
            except (ValueError, OverflowError):
                return token

        # Hex numeric entity.
        if token.startswith("&#x"):
            try:
                return chr(int(token[3:-1], 16))
            except (ValueError, OverflowError):
                return token

        return token

    return HTML_ENTITY_RE.sub(replace, value)


UNICODE_ESCAPE_RE = re.compile(
    r"\\u([0-9A-Fa-f]{4})"
)


def decode_unicode_escapes(value):

    def replace(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return UNICODE_ESCAPE_RE.sub(replace, value)


def decode_once(value):

    # 1. Percent escapes.
    decoded = unquote(value)

    # 2. HTML entities.
    decoded = decode_html_entities(decoded)

    # 3. \uXXXX escapes.
    decoded = decode_unicode_escapes(decoded)

    return decoded


# ---------------------------------------------------------
# Main sanitizer
# ---------------------------------------------------------

def sanitize(body):

    # RULE 1: INVALID_SCHEMA
    if not isinstance(body, dict):
        return make_result("INVALID_SCHEMA")

    channel = body.get("channel")
    output = body.get("output")

    if channel not in VALID_CHANNELS:
        return make_result("INVALID_SCHEMA")

    if not isinstance(output, str):
        return make_result("INVALID_SCHEMA")

    if len(output) > 20000:
        return make_result("INVALID_SCHEMA")

    # RULE 2: ENCODED_PAYLOAD
    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = check_channel(
            channel,
            decoded,
        )

        if decoded_reason != "SAFE":
            return make_result("ENCODED_PAYLOAD")

    # RULE 3: original output
    reason = check_channel(
        channel,
        output,
    )

    return make_result(reason)


# ---------------------------------------------------------
# Vercel native Python handler
# ---------------------------------------------------------

class handler(BaseHTTPRequestHandler):

    def do_POST(self):

        if self.path not in {
            "/sanitize-output",
            "/api/index",
            "/api/index.py",
        }:
            self.send_response(404)
            self.send_header(
                "Content-Type",
                "application/json",
            )
            self.end_headers()

            self.wfile.write(
                b'{"safe":false,"reason":"INVALID_SCHEMA"}'
            )

            return

        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )
        except ValueError:
            content_length = 0

        try:
            raw_body = self.rfile.read(content_length)

            body = json.loads(
                raw_body.decode("utf-8")
            )

            result = sanitize(body)

        except Exception:
            result = make_result("INVALID_SCHEMA")

        response_body = json.dumps(
            result,
            separators=(",", ":"),
        ).encode("utf-8")

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "application/json",
        )

        self.send_header(
            "Content-Length",
            str(len(response_body)),
        )

        self.end_headers()

        self.wfile.write(response_body)

        return

    def do_GET(self):

        response_body = b'{"status":"ok"}'

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "application/json",
        )

        self.send_header(
            "Content-Length",
            str(len(response_body)),
        )

        self.end_headers()

        self.wfile.write(response_body)

        return

    def log_message(self, format, *args):
        return
