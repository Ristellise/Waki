# Waki

*Sniffer for legacy internet bytes.*

Waki takes messy legacy data and runs statistical heuristics on it to figure out its true character encoding. It assumes humans lie, mail clients have bugs, and standards die. It takes the stated HTTP/MIME header, measures it against mathematical byte-guessing, and violently resolves the conflict. 

## Features

* Decouples sniffing logic from specific heuristic libraries via Enum-based backend selection.
* Catches prolific historical fat-finger typos (maps brick-crushing `iso-8895-1` metrics to `latin_1`).
* Resolves `x-user-defined` legacy Netscape Navigator garbage.
* Uses zero-copy `memoryview` slicing for high-performance whitespace/BOM stripping.
* Calculates actual `\ufffd` replacement character ratios to intelligently reject guessed encodings.
* Returns execution logs for every step of its conflict resolution process.

## Installation

```bash
pip install waki
```

Due to differing opinions on correct charset detectors, Waki does not install backends by default. Install your preferred engine alongside Waki:

```bash
pip install charset-normalizer
pip install chardet
pip install faust-cchardet
```

## Backends

Specify your underlying heuristic engine using `Backend` enums. Waki wraps your selection automatically.

* `Backend.CHARSET_NORMALIZER`
* `Backend.CCHARDET`
* `Backend.CHARDET`

## Usage

Instantiate `Waki` with your target backend, then pass in the MIME `Content-Type` header and the raw byte string.

```python
from waki import Waki, Backend

# Initialize with your preferred heuristic engine
sniffer = Waki(backend=Backend.CHARSET_NORMALIZER)

# Messy legacy payload (e.g., Usenet archive, raw email)
content_type = 'text/plain; charset="x-user-defined"'
raw_bytes = b"Robin Alden wrote:\n> \xef\xbf\xbd\xef\xbf\xbd The answer is to send your ODBC.INI file.\xef\xbf\xbd"

text, encoding, logs = sniffer.sniff_content(content_type, raw_bytes)

print(f"Detected: {encoding}")
print(f"Logs:     {logs}")
print(f"Output:   {text}")
```

## HTMLSniffer

Subclass of `Waki` built specifically for web archiving and HTML body parsing. `HTMLSniffer` injects additional regex-based heuristics to extract clues directly from the byte payload.

Features added in this subclass:
* Extracts `<meta charset="X">` and `<meta http-equiv...>` hints.
* Detects `<html lang="ja">` attributes to resolve CJK Shift-JIS / GB18030 conflicts.
* Rejects payloads containing immediate `<script>` hijacks.

```python
from waki import HTMLSniffer, Backend

web_sniffer = HTMLSniffer(backend=Backend.CCHARDET)

http_header = 'text/html; charset="iso-8895-1"' # The famous typo
html_bytes = b'<html><head><meta charset="utf-8"></head><body>Fran\xc3\xa7ois</body></html>'

# HTMLSniffer weighs the HTTP header against the internal meta tag
text, encoding, logs = web_sniffer.sniff_content(http_header, html_bytes)
```

## Architecture Details

Waki extracts a 64KB sample from the provided bytes and runs it through the chosen backend. It simultaneously parses the human-provided header. 

If the backend guess and the header disagree, Waki decodes the sample using the human-provided header and counts the exact ratio of Unicode replacement characters (`\ufffd`). If the failure ratio is under 0.25%, Waki trusts the header. If the failure ratio is high, Waki throws the header out and falls back to the backend's statistical guess. 

Ultimate fallback defaults to `utf-8`.