import codecs
import difflib
import encodings.aliases
from functools import lru_cache
from enum import Enum


class Backend(Enum):
    CHARDET = "chardet"
    CCHARDET = "cchardet"
    CHARSET_NORMALIZER = "charset_normalizer"


@lru_cache(maxsize=1024 * 8)
def codec_exists(enc: str) -> bool:
    """Validates if Python natively supports the given encoding string."""
    if not enc:
        return False
    try:
        codecs.lookup(enc)
        return True
    except LookupError:
        return False


def parse_mime_header(hdr: str) -> tuple[str, dict[str, str]]:
    """Parses Content-Type headers into base MIME and parameter dictionary."""
    if not hdr:
        return "", {}
    parts = hdr.split(";")
    mime = parts[0].strip().lower()
    params = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip().lower()] = v.strip().strip("'\"").lower()
    return mime, params


# Build a flattened list of all encodings and aliases known natively by Python
KNOWN_ENCODINGS = list(
    set(encodings.aliases.aliases.keys()).union(set(encodings.aliases.aliases.values()))
)


@lru_cache(maxsize=1024)
def fuzzy_match_encoding(bad_name: str) -> str | None:
    """Catches slight typos by checking against Python's known internal encodings."""
    if not bad_name:
        return None

    matches = difflib.get_close_matches(bad_name, KNOWN_ENCODINGS, n=1, cutoff=0.75)
    if matches:
        return matches[0]
    return None
