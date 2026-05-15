import importlib
from io import StringIO

from .Utils import Backend, parse_mime_header, codec_exists, fuzzy_match_encoding


class Waki:
    """
    Heuristic encoding detector and resolver for legacy internet data.
    Resolves conflicts between stated MIME headers and statistical byte analysis.
    """

    ENCODING_MAP = {
        "utf_8": "utf_8",
        "utf8": "utf_8",
        "ascii": "utf_8",
        "us_ascii": "utf_8",
        "iso_8859_1": "latin_1",
        "latin1": "latin_1",
        "ms949": "cp949",
        "windows_31j": "cp932",
        "ks_c_5601-1987": "cp949",
        "euc_kr": "cp949",
        "shift_jis": "cp932",
        "sjis": "cp932",
        "iso_8895_1": "latin_1",  # Common historical typo
        "x_user_defined": "utf_8",  # Legacy Netscape fallback
    }
    UNDERSCORE = str.maketrans("-", "_")

    def __init__(self, backend: Backend):
        self.backend = backend
        self._setup_detector()

    def _setup_detector(self):
        """Dynamically loads the requested backend to avoid rigid dependencies."""
        lib = importlib.import_module(self.backend.value)

        if self.backend == Backend.CHARSET_NORMALIZER:

            def detect(b: bytes) -> str | None:
                match = lib.from_bytes(b).best()
                return match.encoding if match else None

            self.detect = detect
        else:
            self.detect = lambda b: lib.detect(b).get("encoding")

    def sniff_content(
        self, content_type: str, raw_bytes: bytes
    ) -> tuple[str | None, str | None, str]:
        """
        Evaluates raw bytes against a provided content_type to safely decode text.

        Returns:
            (decoded_text, final_encoding_used, execution_logs)
        """
        if not raw_bytes:
            return None, None, "Empty payload"

        full_view = memoryview(raw_bytes)

        # Fast strip of BOM/WS
        start = 0
        limit = min(len(full_view), 50)
        while start < limit and full_view[start] in {
            32,
            9,
            10,
            13,
            239,
            187,
            191,
            254,
            255,
        }:
            start += 1

        if start == len(full_view):
            return None, None, "Payload was entirely whitespace/BOM"

        content = full_view[start:]

        # Hook for early rejection
        pre_check_err = self._pre_check(content)
        if pre_check_err:
            return None, None, pre_check_err

        with StringIO() as commentary:
            encoding_data, do_discard = self._resolve_encoding(
                content_type, content, commentary
            )

            if do_discard or encoding_data is None:
                return None, None, f"Discarded: {commentary.getvalue()}"

            try:
                decoded_text = str(content, encoding_data, errors="replace")
                return decoded_text, encoding_data, commentary.getvalue()
            except Exception as e:
                return None, None, f"Catastrophic decode fail: {str(e)}"

    def _pre_check(self, content: memoryview) -> str | None:
        """Hook for subclasses to reject payloads early."""
        return None

    def _get_contextual_hints(
        self,
        view: memoryview,
        header_mime: str,
        http_params: dict,
        commentary: StringIO,
    ) -> tuple[str, str, str | None]:
        """Hook for subclasses to extract encoding hints from the content itself."""
        return header_mime if header_mime else "unknown/content", "", None

    def _resolve_encoding(
        self, content_type_header: str, view: memoryview, commentary: StringIO
    ) -> tuple[str | None, bool]:
        header_mime, http_params = parse_mime_header(content_type_header)

        # Inject possible subclass logic
        resolved_mime, html_enc, lang_hint = self._get_contextual_hints(
            view, header_mime, http_params, commentary
        )


        suggested_encoding = self._normalise_encoding(
            http_params.get("charset") or html_enc
        )

        # Run the backend detector
        detect_sample = view[:65536].tobytes()
        guessed_encoding = self.detect(detect_sample)

        if guessed_encoding:
            guessed_encoding = guessed_encoding.lower()

        # Conflict Resolution Pipeline
        if not guessed_encoding:
            suggested_encoding = suggested_encoding or "utf-8"
        else:
            g_enc = self._normalise_encoding(guessed_encoding)

            if g_enc == "gb18030" and suggested_encoding in {"shift_jis", "cp932"}:
                if lang_hint in {"ja", "jp"}:
                    commentary.write("<gb18030[JPfix]>")
                else:
                    if (
                        self._decode_failure_ratio(suggested_encoding, detect_sample)
                        >= 0.01
                    ):
                        suggested_encoding = g_enc

            elif g_enc == "iso8859_5" and suggested_encoding == "euc_kr":
                if (
                    self._decode_failure_ratio(suggested_encoding, detect_sample)
                    >= 0.01
                ):
                    suggested_encoding = g_enc

            elif suggested_encoding and codec_exists(suggested_encoding):
                fc = self._decode_failure_ratio(suggested_encoding, detect_sample)
                if fc < 0.0025:
                    commentary.write(f"<[UseOrig] fc {fc * 100:.2f}%>")
                else:
                    commentary.write(f"<[UseGuess] fc {fc * 100:.2f}%>")
                    suggested_encoding = g_enc
            else:
                commentary.write(
                    f'<Original "{suggested_encoding}" invalid - using guessed>'
                )
                suggested_encoding = g_enc

        final_encoding = self._normalise_encoding(suggested_encoding)
        if not codec_exists(final_encoding):
            final_encoding = "utf-8"

        return final_encoding, False

    @staticmethod
    def _decode_failure_ratio(enc: str, data: bytes) -> float:
        if not codec_exists(enc):
            return 1.0
        try:
            decoded = data.decode(enc, errors="replace")
            return decoded.count("\ufffd") / max(1, len(decoded))
        except Exception:
            return 1.0

    def _normalise_encoding(self, enc: str) -> str:
        if not enc:
            return ""

        # 1. Base string cleanup
        clean_enc = (
            enc.lower()
            .translate(self.UNDERSCORE)
            .replace("iso_8859_", "iso8859_")
            .replace("windows_", "cp")
        )

        # 2. Check explicit overrides
        mapped_enc = self.ENCODING_MAP.get(clean_enc, clean_enc)

        # 3. Valid native codec check
        if codec_exists(mapped_enc):
            return mapped_enc

        # 4. Difflib typo fallback (e.g., 'iso-8895-1' -> 'iso8859-1')
        fuzzy_enc = fuzzy_match_encoding(clean_enc)
        if fuzzy_enc and codec_exists(fuzzy_enc):
            return fuzzy_enc

        return mapped_enc
