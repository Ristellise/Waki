import re
from io import StringIO

from .Waki import Waki
from .Utils import parse_mime_header


class HTMLSniffer(Waki):
    """
    Extends Waki to extract encoding hints from HTML/XML bodies,
    such as <meta> tags and lang attributes.
    """

    RE_HTML_START = re.compile(
        rb"^.{,1024}<(?:!DOCTYPE|html|head|body|div|p|span|table|!--)", re.I
    )
    RE_LANG_ATTR = re.compile(rb'<html[^>]*?\slang=(["\'])([a-zA-Z\-]+)\1', re.I)
    RE_META_CHARSET = re.compile(rb'<meta[^>]*?\scharset=(["\'])([^"\']+)\1', re.I)
    RE_META_HTTP_EQUIV = re.compile(
        rb'<meta[^>]*?\shttp-equiv=(["\'])content-type\1[^>]*?\scontent=(["\'])([^"\']+)\2',
        re.I,
    )
    SCRIPT_HIJACK = re.compile(rb"[\r\n ]*^<(?:script)", re.IGNORECASE)

    def _pre_check(self, content: memoryview) -> str | None:
        if self.SCRIPT_HIJACK.match(content[:16].tobytes()):
            return "Rejected: Script Hijack detected at start of body"
        return None

    def _get_contextual_hints(
        self,
        view: memoryview,
        header_mime: str,
        http_params: dict,
        commentary: StringIO,
    ) -> tuple[str, str, str | None]:
        head_sample = view[:4096].tobytes()
        resolved_mime = header_mime if header_mime else "unknown/content"

        # 1. HTML Verification
        if self.RE_HTML_START.search(head_sample[:2048]):
            commentary.write("<text/html>")
            resolved_mime = "text/html"

        # 2. Meta Charset Extraction
        html_enc = ""
        m = self.RE_META_CHARSET.search(head_sample)
        if m:
            html_enc = m.group(2).decode("ascii", errors="ignore")
        else:
            m = self.RE_META_HTTP_EQUIV.search(head_sample)
            if m:
                _, params = parse_mime_header(
                    m.group(3).decode("ascii", errors="ignore")
                )
                html_enc = params.get("charset", "")

        # 3. Lang Attribute Extraction
        lang_hint = None
        m = self.RE_LANG_ATTR.search(head_sample)
        if m:
            lang_hint = m.group(2).decode("ascii", "ignore").lower()

        return resolved_mime, html_enc, lang_hint
