import pytest
from Waki import Waki, HTMLSniffer, Backend
from Waki.Utils import fuzzy_match_encoding

# ==========================================
# 1. Backend Initialization Tests
# ==========================================

@pytest.mark.parametrize("backend_enum", [
    Backend.CHARSET_NORMALIZER, 
    Backend.CHARDET, 
    Backend.CCHARDET
])
def test_backend_loading(backend_enum):
    """Ensures all 3 backends load dynamically without crashing."""
    try:
        sniffer = Waki(backend=backend_enum)
        assert callable(sniffer.detect)
    except ImportError:
        pytest.skip(f"Backend {backend_enum.value} is not installed.")


# ==========================================
# 2. Core Waki Sniffing Tests
# ==========================================

def test_x_user_defined_fallback():
    """Tests if Netscape's garbage x-user-defined falls back to utf_8."""
    sniffer = Waki(backend=Backend.CHARSET_NORMALIZER)
    ctype = 'text/plain; charset="x-user-defined"'
    
    # Payload contains the UTF-8 replacement character \xef\xbf\xbd
    raw_bytes = b"Robin Alden wrote:\n> \xef\xbf\xbd\xef\xbf\xbd The answer is ODBC."
    
    text, enc, logs = sniffer.sniff_content(ctype, raw_bytes)
    
    assert enc == "utf_8"
    assert text is not None and "The answer is ODBC" in text
    assert text.count("\ufffd") == 2


def test_fat_finger_brick_crushing_typo():
    """Tests if the famous iso-8895-1 typo maps to latin_1."""
    sniffer = Waki(backend=Backend.CHARSET_NORMALIZER)
    ctype = 'text/plain; charset="iso-8895-1"'
    
    # 0xE7 is the latin-1 byte for 'ç' (Fixed my bad French!)
    raw_bytes = b"Fran\xe7ois"
    
    text, enc, logs = sniffer.sniff_content(ctype, raw_bytes)
    
    assert enc == "latin_1"
    assert "François" in text


def test_fuzzy_matcher():
    """Tests if the difflib fuzzy matcher catches weird typos."""
    assert fuzzy_match_encoding("windws-1252") in ("cp1252", "windows_1252")


# ==========================================
# 3. HTMLSniffer Context Tests
# ==========================================

def test_html_script_hijack_rejection():
    """Ensures HTML payloads starting with <script> are violently rejected."""
    sniffer = HTMLSniffer(backend=Backend.CHARSET_NORMALIZER)
    ctype = 'text/html'
    
    raw_bytes = b"   \r\n <sCrIpT>alert('hijack')</script>"
    text, enc, logs = sniffer.sniff_content(ctype, raw_bytes)
    
    assert text is None
    assert enc is None
    assert "Rejected: Script Hijack" in logs


def test_html_meta_tag_extraction():
    """Ensures HTMLSniffer extracts and favors inner HTML <meta> tags."""
    sniffer = HTMLSniffer(backend=Backend.CHARSET_NORMALIZER)
    
    # The HTTP header claims us-ascii (human lie)
    ctype = 'text/html; charset="us-ascii"'
    
    # The HTML meta tag claims utf-8, and the payload actually IS utf-8
    raw_bytes = b'<html><head><meta charset="utf-8"></head><body>\xe6\xb0\xb4</body></html>'
    
    text, enc, logs = sniffer.sniff_content(ctype, raw_bytes)
    
    assert enc == "utf_8"
    assert text is not None and "水" in text