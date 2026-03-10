"""7-stage sanitization pipeline orchestrator."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .delimiters import DelimiterStats, sanitize_delimiters
from .directives import DirectiveStats, sanitize_directives
from .encoded import EncodedStats, sanitize_encoded
from .exfiltration import ExfiltrationStats, sanitize_exfiltration
from .html import HtmlStats, sanitize_html
from .unicode import UnicodeStats, sanitize_unicode

_HTML_EXTENSIONS = frozenset({".html", ".htm", ".xhtml", ".svg"})
_HTML_CONTENT_RE = re.compile(r"^\s*(<(!DOCTYPE|html)\b)", re.IGNORECASE)


@dataclass
class PipelineStats:
    """Combined statistics from all sanitization stages."""

    html: HtmlStats = field(default_factory=HtmlStats)
    unicode: UnicodeStats = field(default_factory=UnicodeStats)
    encoded: EncodedStats = field(default_factory=EncodedStats)
    exfiltration: ExfiltrationStats = field(default_factory=ExfiltrationStats)
    delimiters: DelimiterStats = field(default_factory=DelimiterStats)
    directives: DirectiveStats = field(default_factory=DirectiveStats)

    def to_flat_dict(self) -> dict[str, int]:
        """Flatten all stats into a single dict for serialization."""
        flat: dict[str, int] = {}
        named_sections = [
            ("html", asdict(self.html)),
            ("unicode", asdict(self.unicode)),
            ("encoded", asdict(self.encoded)),
            ("exfiltration", asdict(self.exfiltration)),
            ("delimiters", asdict(self.delimiters)),
            ("directives", asdict(self.directives)),
        ]
        for section_name, section_dict in named_sections:
            for key, value in section_dict.items():
                flat[f"{section_name}_{key}"] = value
        return flat

    def total_detections(self) -> int:
        """Total number of injection vectors detected across all stages."""
        return sum(self.to_flat_dict().values())

    def risk_level(self) -> str:
        """Classify risk based on detection counts."""
        total = self.total_detections()
        if total == 0:
            return "low"
        if total <= 3:
            return "medium"
        if total <= 10:
            return "high"
        return "critical"


@dataclass
class PipelineResult:
    """Result from the sanitization pipeline."""

    content: str
    stats: PipelineStats
    input_size: int
    output_size: int


def looks_like_html(content: str, file_path: str | None = None) -> bool:
    """Detect if content is HTML based on extension or content sniffing."""
    if file_path:
        dot = file_path.rfind(".")
        if dot != -1 and file_path[dot:].lower() in _HTML_EXTENSIONS:
            return True
    return bool(_HTML_CONTENT_RE.search(content))


def sanitize(html_content: str) -> PipelineResult:
    """Run the full 7-stage pipeline on HTML content.

    1. Parse HTML (BeautifulSoup)
    2. Strip hidden elements (display:none, off-screen, same-color)
    3. Strip dangerous tags (script, style, noscript, meta, link) + comments
    4. Convert HTML to Markdown
    5. Unicode sanitization (zero-width, bidi, control chars, NFKC)
    6. Encoded payload detection (base64/hex with instruction patterns)
    7. Exfiltration URL detection (suspicious markdown images)
    8. LLM delimiter stripping
    """
    input_size = len(html_content.encode("utf-8"))
    pipeline_stats = PipelineStats()

    content, html_stats = sanitize_html(html_content)
    pipeline_stats.html = html_stats

    content, unicode_stats = sanitize_unicode(content)
    pipeline_stats.unicode = unicode_stats

    content, encoded_stats = sanitize_encoded(content)
    pipeline_stats.encoded = encoded_stats

    content, exfil_stats = sanitize_exfiltration(content)
    pipeline_stats.exfiltration = exfil_stats

    content, delimiter_stats = sanitize_delimiters(content)
    pipeline_stats.delimiters = delimiter_stats

    content, directive_stats = sanitize_directives(content)
    pipeline_stats.directives = directive_stats

    output_size = len(content.encode("utf-8"))

    return PipelineResult(
        content=content,
        stats=pipeline_stats,
        input_size=input_size,
        output_size=output_size,
    )


def sanitize_text(text: str) -> PipelineResult:
    """Run the text-only pipeline (no HTML parsing).

    For non-HTML content (markdown files, plain text, source code).
    Runs stages 5-8 only.
    """
    input_size = len(text.encode("utf-8"))
    pipeline_stats = PipelineStats()

    content = text

    content, unicode_stats = sanitize_unicode(content)
    pipeline_stats.unicode = unicode_stats

    content, encoded_stats = sanitize_encoded(content)
    pipeline_stats.encoded = encoded_stats

    content, exfil_stats = sanitize_exfiltration(content)
    pipeline_stats.exfiltration = exfil_stats

    content, delimiter_stats = sanitize_delimiters(content)
    pipeline_stats.delimiters = delimiter_stats

    content, directive_stats = sanitize_directives(content)
    pipeline_stats.directives = directive_stats

    output_size = len(content.encode("utf-8"))

    return PipelineResult(
        content=content,
        stats=pipeline_stats,
        input_size=input_size,
        output_size=output_size,
    )
