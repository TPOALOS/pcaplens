"""Parse HTTP/1.x messages out of reassembled TCP stream bytes."""
import re
import zlib

REQ_RE = re.compile(rb"^([A-Z]{3,10}) (\S+) HTTP/(1\.[01])\r\n")
RESP_RE = re.compile(rb"^HTTP/(1\.[01]) (\d{3})[^\r\n]*\r\n")
MAX_MESSAGES = 2000
MAX_BODY = 64 * 1024 * 1024


def looks_like_http(data, response):
    return bool((RESP_RE if response else REQ_RE).match(data[:200]))


def parse_headers(block):
    headers = {}
    for line in block.split(b"\r\n"):
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return headers


def decode_chunked(data):
    """Return (body, consumed_bytes, complete)."""
    body, pos = bytearray(), 0
    while True:
        eol = data.find(b"\r\n", pos)
        if eol == -1:
            return bytes(body), pos, False
        try:
            size = int(data[pos:eol].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return bytes(body), pos, False
        pos = eol + 2
        if size == 0:
            end = data.find(b"\r\n\r\n", pos - 2)
            return bytes(body), (end + 4 if end != -1 else len(data)), True
        if pos + size > len(data):
            body += data[pos:]
            return bytes(body), len(data), False
        body += data[pos:pos + size]
        pos += size + 2
        if len(body) > MAX_BODY:
            return bytes(body), pos, False


def decompress(body, encoding, limit=MAX_BODY):
    """Inflate gzip/deflate bodies with a hard size cap (zip-bomb safe). Returns (data, ok)."""
    enc = (encoding or "").lower()
    if enc not in ("gzip", "x-gzip", "deflate"):
        return body, True
    try:
        d = zlib.decompressobj(47 if enc != "deflate" else 15)
        out = d.decompress(body, limit)
        return out, not d.unconsumed_tail
    except zlib.error:
        try:
            d = zlib.decompressobj(-15)
            return d.decompress(body, limit), True
        except zlib.error:
            return body, False


def parse_messages(data, response):
    """Return a list of dicts: kind, method/target or status, headers, body, truncated."""
    out, pos = [], 0
    while pos < len(data) and len(out) < MAX_MESSAGES:
        head_end = data.find(b"\r\n\r\n", pos)
        if head_end == -1:
            break
        m = (RESP_RE if response else REQ_RE).match(data[pos:pos + 8192])
        if not m:
            break
        headers = parse_headers(data[pos + m.end() - 2:head_end])
        start = head_end + 4
        msg = {"kind": "response" if response else "request", "headers": headers, "offset": pos}
        if response:
            msg["status"] = int(m.group(2))
        else:
            msg["method"], msg["target"] = m.group(1).decode(), m.group(2).decode("latin-1")
        no_body = response and (msg["status"] < 200 or msg["status"] in (204, 304))
        truncated = False
        if no_body:
            body, consumed = b"", 0
        elif "chunked" in headers.get("transfer-encoding", "").lower():
            body, consumed, complete = decode_chunked(data[start:])
            truncated = not complete
        elif "content-length" in headers and headers["content-length"].isdigit():
            n = int(headers["content-length"])
            body = data[start:start + n]
            consumed, truncated = len(body), len(body) < n
        elif response:
            body, consumed = data[start:], len(data) - start
        else:
            body, consumed = b"", 0
        msg["body"], msg["truncated"] = body, truncated
        out.append(msg)
        pos = start + consumed
        if truncated:
            break
    return out
