"""Shared cleaning and label normalization for the two email CSV sources."""
from collections import Counter
from html import unescape
from html.parser import HTMLParser
import re
import pandas as pd

LABELS = {"Safe Email": 0, "Phishing Email": 1}

class _TextOnlyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style"}:
            self.hidden_depth += 1
        elif tag.lower() in {"br", "p", "div", "li", "tr", "td", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1
        elif tag.lower() in {"p", "div", "li", "tr", "td"}:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)

def clean_email_text(value, limit=5000):
    """Strip markup, truncate, lowercase and normalize punctuation whitespace."""
    if pd.isna(value):
        return ""
    raw = unescape(str(value))
    parser = _TextOnlyParser()
    try:
        parser.feed(raw)
        text = " ".join(parser.parts)
    except Exception:
        text = re.sub(r"<[^>]*>", " ", raw)
    text = text[:limit].lower()
    text = re.sub(r"\s+([,.;:!?])", r"\1", text)
    text = re.sub(r"([,.;:!?])(?=\S)", r"\1 ", text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n+ *", "\n", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()

def load_email_csv(path, deduplicate=True):
    """Return only `[text, label]` rows and cleaning counts.

    Empty bodies are removed. Cleaning and truncation are identical for both
    classes. Exact normalized-text duplicates are removed before any split;
    texts with contradictory labels are excluded rather than arbitrarily kept.
    """
    raw = pd.read_csv(path, encoding="utf-8", dtype={"Email Text": "string"})
    required = {"Email Text", "Email Type"}
    if not required.issubset(raw.columns):
        raise ValueError(f"Expected email columns {sorted(required)}; found {list(raw.columns)}")
    counts = {
        "raw_rows": int(len(raw)),
        "raw_label_counts": {str(k): int(v) for k, v in raw["Email Type"].value_counts(dropna=False).items()},
        "empty_or_missing_before_cleaning": int(raw["Email Text"].isna().sum() + raw["Email Text"].fillna("").astype(str).str.strip().eq("").sum()),
    }
    unknown = sorted(set(raw["Email Type"].dropna().unique()) - set(LABELS))
    if unknown:
        raise ValueError(f"Unexpected email labels in {path}: {unknown}")
    frame = raw[["Email Text", "Email Type"]].copy()
    frame["text"] = frame["Email Text"].map(clean_email_text)
    frame["label"] = frame["Email Type"].map(LABELS).astype("int8")
    frame = frame.loc[frame["text"].ne(""), ["text", "label"]].copy()
    counts["nonempty_after_cleaning_before_dedup"] = int(len(frame))
    if deduplicate:
        grouped = frame.groupby("text", sort=False)["label"]
        conflicting = set(grouped.nunique().loc[lambda s: s > 1].index)
        counts["conflicting_duplicate_texts_removed"] = int(len(conflicting))
        frame = frame.loc[~frame["text"].isin(conflicting)]
        before_dedup = len(frame)
        frame = frame.drop_duplicates(subset="text", keep="first").reset_index(drop=True)
        counts["exact_duplicates_removed"] = int(before_dedup - len(frame))
    else:
        counts["conflicting_duplicate_texts_removed"] = 0
        counts["exact_duplicates_removed"] = 0
        frame = frame.reset_index(drop=True)
    counts["clean_rows"] = int(len(frame))
    counts["clean_label_counts"] = {str(int(k)): int(v) for k, v in frame["label"].value_counts().items()}
    return frame[["text", "label"]], counts

def marker_tokens_from_training(texts):
    """Extract likely source/header/signature tokens from training text only."""
    marker_words = {
        "subject", "from", "to", "cc", "bcc", "sent", "date", "reply", "reply-to",
        "received", "forwarded", "original", "mime", "version", "content", "transfer",
        "encoding", "message-id", "unsubscribe", "listserv", "mailing", "list", "enron",
        "wrote", "writes", "regards", "sincerely", "cheers", "attached", "attachment",
        "headers", "eol", "ect", "hou", "hpl", "xo", "com",
    }
    month_and_weekdays = set("january february march april may june july august september october november december monday tuesday wednesday thursday friday saturday sunday jan feb mar apr jun jul aug sep sept oct nov dec mon tue wed thu fri sat sun".split())
    marker_words |= month_and_weekdays
    email_re = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
    token_re = re.compile(r"[a-z][a-z0-9_-]{1,}")
    header_re = re.compile(r"(?im)^\s*(?:from|to|cc|bcc|subject|date|sent|reply-to|received|message-id|mime-version|content-type)\s*:\s*(.*)$")
    signoff_re = re.compile(r"(?im)^\s*(?:regards|sincerely|best|best regards|thanks|cheers)[,\s]+([a-z][a-z .'-]{1,45})\s*$")
    for text in texts:
        for match in email_re.findall(text):
            marker_words.update(token_re.findall(match.lower()))
        for pattern in (header_re, signoff_re):
            for match in pattern.findall(text):
                marker_words.update(token_re.findall(match.lower()))
        for date in re.findall(r"\b(?:19|20)\d{2}\b|\b\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?\b", text):
            marker_words.update(token_re.findall(date.lower()))
    return marker_words

def source_marker(feature, marker_tokens):
    parts = re.findall(r"[a-z][a-z0-9_-]*", feature.lower())
    return any(part in marker_tokens for part in parts) or "@" in feature
