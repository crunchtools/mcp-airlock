"""Tests for HTML sanitization module."""

from __future__ import annotations

from mcp_airlock_crunchtools.sanitize.html import sanitize_html


class TestHtmlSanitization:
    """Test hidden element removal, tag stripping, comment removal."""

    def test_strips_display_none(self) -> None:
        html = '<div>visible</div><div style="display:none">hidden injection</div>'
        _, stats = sanitize_html(html)
        assert stats.hidden_elements == 1

    def test_strips_display_none_with_space(self) -> None:
        html = '<div style="display: none">hidden</div><p>visible</p>'
        _, stats = sanitize_html(html)
        assert stats.hidden_elements == 1

    def test_strips_visibility_hidden(self) -> None:
        html = '<span style="visibility:hidden">invisible</span><p>visible</p>'
        _, stats = sanitize_html(html)
        assert stats.hidden_elements == 1

    def test_strips_opacity_zero(self) -> None:
        html = '<div style="opacity:0">transparent</div><p>visible</p>'
        _, stats = sanitize_html(html)
        assert stats.hidden_elements == 1

    def test_strips_hidden_attribute(self) -> None:
        html = '<div hidden>hidden</div><p>visible</p>'
        _, stats = sanitize_html(html)
        assert stats.hidden_elements == 1

    def test_strips_off_screen_text_indent(self) -> None:
        html = '<div style="text-indent:-9999px">off screen</div><p>visible</p>'
        _, stats = sanitize_html(html)
        assert stats.off_screen_elements == 1

    def test_strips_off_screen_absolute_left(self) -> None:
        html = '<div style="position:absolute;left:-9999px">off screen</div>'
        _, stats = sanitize_html(html)
        assert stats.off_screen_elements == 1

    def test_strips_off_screen_font_size_zero(self) -> None:
        html = '<span style="font-size:0">tiny</span><p>visible</p>'
        _, stats = sanitize_html(html)
        assert stats.off_screen_elements == 1

    def test_strips_same_color_text(self) -> None:
        html = '<div style="color:white;background:white">invisible</div>'
        _, stats = sanitize_html(html)
        assert stats.same_color_text == 1

    def test_strips_same_color_hex(self) -> None:
        html = '<div style="color:#fff;background-color:#ffffff">invisible</div>'
        _, stats = sanitize_html(html)
        assert stats.same_color_text == 1

    def test_strips_script_tags(self) -> None:
        html = '<p>text</p><script>alert(1)</script>'
        markdown, stats = sanitize_html(html)
        assert "alert" not in markdown
        assert stats.script_tags == 1

    def test_strips_style_tags(self) -> None:
        html = '<style>.evil{}</style><p>text</p>'
        _, stats = sanitize_html(html)
        assert stats.style_tags == 1

    def test_strips_noscript_tags(self) -> None:
        html = '<noscript>fallback</noscript><p>text</p>'
        _, stats = sanitize_html(html)
        assert stats.noscript_tags == 1

    def test_strips_meta_link_tags(self) -> None:
        html = '<meta charset="utf-8"><link rel="stylesheet"><p>text</p>'
        _, stats = sanitize_html(html)
        assert stats.meta_tags == 2

    def test_strips_html_comments(self) -> None:
        html = '<p>text</p><!-- secret injection -->'
        markdown, stats = sanitize_html(html)
        assert "secret" not in markdown
        assert stats.html_comments == 1

    def test_converts_to_markdown(self) -> None:
        html = '<h1>Title</h1><p>Paragraph text.</p>'
        markdown, _ = sanitize_html(html)
        assert "Title" in markdown
        assert "Paragraph text." in markdown

    def test_clean_html(self) -> None:
        html = '<p>Just a paragraph.</p>'
        _, stats = sanitize_html(html)
        assert stats.hidden_elements == 0
        assert stats.script_tags == 0
        assert stats.html_comments == 0
