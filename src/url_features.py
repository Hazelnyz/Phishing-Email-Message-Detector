"""Offline lexical URL features. This module never resolves or fetches URLs."""
from collections import Counter
import ipaddress
import math
import re
from urllib.parse import urlsplit

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly",
    "buff.ly", "rebrand.ly", "lnkd.in", "rb.gy", "shorturl.at",
}
SPECIALS = "!#$%&'()*+,-./:;=?@[]_~%"

def _split_url(value):
    raw = str(value or "").strip()
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", raw):
        raw = "http://" + raw
    try:
        return raw, urlsplit(raw)
    except ValueError:
        return raw, urlsplit("http://invalid.invalid")

def url_features(value):
    """Extract only features computed from the URL string itself."""
    raw, parsed = _split_url(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    labels = [part for part in host.split(".") if part]
    tld = labels[-1] if len(labels) > 1 else "<none>"
    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except ValueError:
        has_ip = 0
    chars = len(raw) or 1
    frequencies = Counter(raw)
    entropy = -sum((count / chars) * math.log2(count / chars) for count in frequencies.values())
    path = parsed.path or ""
    query = parsed.query or ""
    return {
        "url_length": len(raw),
        "domain_length": len(host),
        "digit_ratio": sum(c.isdigit() for c in raw) / chars,
        "letter_ratio": sum(c.isalpha() for c in raw) / chars,
        "special_char_count": sum(c in SPECIALS for c in raw),
        "hyphen_count": raw.count("-"),
        "dot_count": raw.count("."),
        "slash_count": raw.count("/"),
        "question_count": raw.count("?"),
        "equals_count": raw.count("="),
        "ampersand_count": raw.count("&"),
        "at_count": raw.count("@"),
        "subdomain_count": max(0, len(labels) - 2),
        "has_ip_host": has_ip,
        "has_punycode": int("xn--" in host),
        "tld": tld,
        "shortener": int(host in SHORTENERS),
        "path_depth": sum(bool(segment) for segment in path.split("/")),
        "query_length": len(query),
        "shannon_entropy": entropy,
        "https": int(parsed.scheme.lower() == "https"),
    }
