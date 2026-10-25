"""
signal_detector.py
-------------------
Rule/heuristic-based phishing signal detector. This module is independent of
the ML model: it inspects raw message text (and optional sender/URL metadata)
for known phishing indicators and returns a structured list of signals with
weights and human-readable explanations.

This module NEVER opens, visits, or fetches any URL. All URL analysis is done
by parsing the URL string locally with Python's standard library.

Signals detected:
  - Urgency / time-pressure language
  - Threats (account suspension, legal action, loss of access)
  - Credential / password / OTP requests
  - Suspicious URLs (shorteners, lookalike domains, IP-based URLs, excessive
    subdomains, non-HTTPS links, suspicious TLDs)
  - Misleading / lookalike domains (typosquatting of a trusted domain)
  - Sender/domain mismatch (when sender metadata is supplied)
  - Suspicious payment / financial requests
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Keyword / phrase banks
# ---------------------------------------------------------------------------

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bright away\b",
    r"\bwithin \d+\s*(hour|hr|minute|min)s?\b", r"\btoday\b.*\b(only|deadline)\b",
    r"\bfinal (warning|notice)\b", r"\blast chance\b", r"\bexpir(es|ing|ed)\b",
    r"\bbefore midnight\b", r"\bas soon as possible\b", r"\basap\b",
    r"\blimited (time|slots|seats)\b", r"\bhurry\b", r"\btime[- ]sensitive\b",
]

THREAT_PATTERNS = [
    r"\bsuspend(ed|sion)?\b", r"\bdeactivat(e|ed|ion)\b", r"\bterminat(e|ed|ion)\b",
    r"\block(ed|out)?\b.*\baccount\b", r"\blegal action\b", r"\bpenalty\b",
    r"\bpermanently (lost|locked|deleted|removed)\b", r"\bviolation\b",
    r"\bwithheld\b", r"\brevoke(d)?\b", r"\bdisabl(e|ed)\b", r"\bban(ned)?\b",
    r"\bfine\b",
]

# High severity: asks for information that must never be sent in a message.
# Deliberately accept common SMS spellings and informal request constructions.
SENSITIVE_INFO_PATTERNS = [
    r"\b(?:credit|debit)\s*(?:card)?\s*(?:details?|number|no\.?|info)\b",
    r"\b(?:card\s*)?(?:cvv|cvc|expiry|expiration|exp\.?\s*date|pin)\b",
    r"\b(?:bank|acct|account)\s*(?:account\s*)?(?:details?|number|no\.?|info)\b",
    r"\b(?:upi|ifsc|net\s*banking|netbanking)\b(?:\s*(?:details?|id|pin|login|info))?",
    r"\b(?:aadhaar|aadhar|pan|passport|date\s*of\s*birth|dob|registration\s*(?:number|no\.?))\b",
    r"\b(?:one[- ]time\s*)?(?:otp|pwd|password|passcode|pin)\b",
    r"\b(?:send|share|give|gimme|provide|reply\s+with|tell)\s+(?:(?:me|us)\s+)?(?:ur|your|u|the)?\s*(?:credit|debit|card|bank|acct|account|upi|ifsc|net\s*banking|aadhaar|aadhar|pan|passport|dob|date\s*of\s*birth|registration|otp|pwd|password|pin|cvv|cvc)\b",
    r"\b(?:details?|info|number|no\.?)\s+(?:of\s+)?(?:ur|your|u|credit|debit|card|bank|acct|account|upi|ifsc|aadhaar|pan|passport|otp|password|pwd|cvv)\b",
    r"\b(?:ur|your|u)\s+(?:card|bank|acct|account|upi|ifsc|aadhaar|pan|passport|otp|password|pwd|cvv)\s+(?:details?|info|number|no\.?)\b",
]
CREDENTIAL_PATTERNS = SENSITIVE_INFO_PATTERNS + [
    r"\bone[- ]time password\b", r"\bverify (?:ur|your|u) (?:identity|account|password)\b",
    r"\blogin (?:credentials|details)\b", r"\busername and password\b",
    r"\b6[- ]digit (?:code|otp)\b",
]

PAYMENT_PATTERNS = [
    r"\brs\.?\s*[\d,]+\b", r"\b(pay|transfer|send money|processing fee|deposit)\b.*\brs\.?\s*[\d,]+\b",
    r"\b(?:pay|make\s+(?:the\s+)?payment|fee\s+payment)\b.*\b(?:by|via|through|now|today|portal|due|last\s+date)\b",
    r"\bpayment\s+(?:is\s+)?(?:due|required|pending)\b",
    r"\bbank details\b", r"\bupi\b", r"\bclaim (your|the) (prize|reward|refund|scholarship)\b",
    r"\bprocessing fee\b", r"\bcaution deposit\b", r"\bwire transfer\b",
]

TRUSTED_DOMAINS = ["vit.ac.in", "vitstudent.ac.in"]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
                   "ow.ly", "buff.ly", "rebrand.ly"}

SUSPICIOUS_TLDS = {".xyz", ".top", ".info", ".ru", ".click", ".site", ".club",
                    ".work", ".support", ".gq", ".tk"}

URL_REGEX = re.compile(r'(https?://[^\s<>"\')]+|www\.[^\s<>"\')]+)', re.IGNORECASE)
IP_HOST_REGEX = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _extract_urls(text: str):
    raw_matches = URL_REGEX.findall(text or "")
    return [m.rstrip(".,;:!?)") for m in raw_matches]


def _domain_edit_distance(a: str, b: str) -> int:
    """Simple Levenshtein distance for lookalike-domain detection."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    dp = list(range(lb + 1))
    for i in range(1, la + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, lb + 1):
            tmp = dp[j]
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + cost)
            prev = tmp
    return dp[lb]


def analyze_urls(text: str):
    """Analyze every URL string found in the text. Never fetches a URL."""
    urls = _extract_urls(text)
    findings = []
    for raw in urls:
        url = raw if raw.startswith("http") else "http://" + raw
        try:
            parsed = urlparse(url)
        except Exception:
            findings.append({
                "url": raw, "issues": ["Could not be parsed; malformed URL"],
                "severity": "medium",
            })
            continue

        host = (parsed.hostname or "").lower()
        issues = []
        severity = "low"

        if not url.lower().startswith("https://"):
            issues.append("Link does not use HTTPS")

        if host in URL_SHORTENERS:
            issues.append(f"Uses a URL shortener ({host}) that hides the real destination")
            severity = "high"

        if IP_HOST_REGEX.match(host):
            issues.append("Uses a raw IP address instead of a domain name")
            severity = "high"

        if host.count(".") >= 3:
            issues.append("Unusually long chain of subdomains, often used to disguise the real domain")
            severity = "high"

        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                issues.append(f"Uses an uncommon top-level domain ({tld}) frequently abused for phishing")
                severity = "high"
                break

        for trusted in TRUSTED_DOMAINS:
            if trusted in host and host != trusted and not host.endswith("." + trusted):
                issues.append(f"Mentions a trusted domain ({trusted}) but is not actually hosted there")
                severity = "high"
            dist = _domain_edit_distance(host.replace("www.", ""), trusted)
            if 0 < dist <= 3 and host != trusted:
                issues.append(f"Looks like a lookalike / typosquat of the trusted domain '{trusted}'")
                severity = "high"

        try:
            from src.lookalike import inspect_domain
            domain_check = inspect_domain(host)
            if domain_check["suspicious"]:
                issues.extend(domain_check["flags"])
                severity = "high"
        except (ImportError, ValueError):
            pass

        if issues:
            findings.append({"url": raw, "issues": issues, "severity": severity})
        else:
            findings.append({"url": raw, "issues": [], "severity": "low"})

    return findings


def check_sender_mismatch(sender: str, claimed_org: str = None):
    """Compares a sender email/domain against trusted domains, if provided."""
    if not sender:
        return None
    sender = sender.strip().lower()
    domain = sender.split("@")[-1] if "@" in sender else sender

    is_trusted = any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS)
    if is_trusted:
        return {"mismatch": False, "detail": f"Sender domain '{domain}' matches a known trusted domain."}

    for trusted in TRUSTED_DOMAINS:
        dist = _domain_edit_distance(domain, trusted)
        if 0 < dist <= 3:
            return {
                "mismatch": True,
                "detail": f"Sender domain '{domain}' closely resembles trusted domain '{trusted}' "
                          f"but does not match exactly — possible spoofing.",
            }

    return {
        "mismatch": True,
        "detail": f"Sender domain '{domain}' is not a recognised institutional domain. "
                  f"Treat messages claiming official authority from this sender with caution.",
    }


def _match_any(patterns, text):
    hits = []
    for pat in patterns:
        if re.search(pat, text, flags=re.IGNORECASE):
            hits.append(pat)
    return hits


def _matched_text(patterns, text):
    found = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(0).strip()
            if value and value not in found:
                found.append(value)
    return found


def detect_signals(message: str, sender: str = None, url_hint: str = None):
    """
    Main entry point. Returns a dict:
      {
        "signals": [ {category, description, severity, weight}, ... ],
        "url_findings": [...],
        "sender_check": {...} or None,
        "total_weight": float
      }
    """
    text = message or ""
    if url_hint:
        text = text + " " + url_hint

    signals = []

    urgency_hits = _match_any(URGENCY_PATTERNS, text)
    if urgency_hits:
        signals.append({
            "category": "Urgency / Time Pressure",
            "description": "The message uses urgent or time-pressuring language to rush the reader into acting "
                            "without thinking (e.g. deadlines measured in hours).",
            "severity": "medium",
            "weight": 15,
            "evidence": _matched_text(urgency_hits, text),
        })

    threat_hits = _match_any(THREAT_PATTERNS, text)
    if threat_hits:
        signals.append({
            "category": "Threats / Negative Consequences",
            "description": "The message threatens a negative consequence (account suspension, loss of access, "
                            "penalties) if the reader does not comply.",
            "severity": "high",
            "weight": 20,
            "evidence": _matched_text(threat_hits, text),
        })

    cred_hits = _match_any(CREDENTIAL_PATTERNS, text)
    if cred_hits:
        signals.append({
            "category": "Credential / OTP Request",
            "description": "The message asks the reader to send or enter a password, OTP, PIN, or other "
                            "credential. Legitimate organisations do not ask for this over message or email.",
            "severity": "critical",
            "weight": 30,
            "evidence": _matched_text(cred_hits, text),
        })

    payment_hits = _match_any(PAYMENT_PATTERNS, text)
    if payment_hits:
        signals.append({
            "category": "Suspicious Payment / Financial Request",
            "description": "The message references a monetary amount, bank/UPI detail, or payment action, "
                            "often paired with urgency — a common lure in financial phishing.",
            "severity": "high",
            "weight": 20,
            "evidence": _matched_text(payment_hits, text),
        })

    url_findings = analyze_urls(text)
    url_weight = 0
    for f in url_findings:
        if f["issues"]:
            url_weight = max(url_weight, 25 if f["severity"] == "high" else 10)
    if url_findings and any(f["issues"] for f in url_findings):
        signals.append({
            "category": "Suspicious URL",
            "description": "One or more links in the message show signs of being unsafe "
                            "(shorteners, lookalike domains, raw IPs, or unusual TLDs). "
                            "The link was analysed as text only — it was not visited.",
            "severity": "high",
            "weight": url_weight,
            "evidence": [f["url"] for f in url_findings if f["issues"]],
        })
    elif url_findings:
        signals.append({
            "category": "Link Present",
            "description": "The message contains a link. No obvious red flags were found in the URL string "
                            "itself, but this does not guarantee the destination is safe.",
            "severity": "low",
            "weight": 5,
            "evidence": [f["url"] for f in url_findings],
        })

    sender_check = check_sender_mismatch(sender) if sender else None
    if sender_check and sender_check["mismatch"]:
        signals.append({
            "category": "Sender / Domain Mismatch",
            "description": sender_check["detail"],
            "severity": "high",
            "weight": 20,
            "evidence": [sender.split("@")[-1]],
        })

    total_weight = sum(s["weight"] for s in signals)

    return {
        "signals": signals,
        "url_findings": url_findings,
        "sender_check": sender_check,
        "total_weight": total_weight,
    }
