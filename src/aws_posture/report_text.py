"""Shared text escaping for generated Markdown and HTML reports."""

from __future__ import annotations

import html

_MARKDOWN_REPLACEMENTS = (
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
    ("`", "'"),
    ("|", "\\|"),
    ("!", "\\!"),
    ("[", "\\["),
    ("]", "\\]"),
    ("(", "\\("),
    (")", "\\)"),
    ("\r", " "),
    ("\n", " "),
)


def md_escape(value) -> str:
    """Escape untrusted scanner output for inclusion in a Markdown table or line."""
    text = str(value or "")
    for character, replacement in _MARKDOWN_REPLACEMENTS:
        text = text.replace(character, replacement)
    return text


def html_escape(value) -> str:
    """Escape untrusted scanner output for inclusion in generated HTML."""
    return html.escape("" if value is None else str(value))
