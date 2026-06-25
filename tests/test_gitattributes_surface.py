"""`.gitattributes` and `.gitignore` are classified as gitconfig sensitive surfaces.

A `.gitattributes` change can suppress diff visibility (e.g. `-diff` attribute),
so modifying it should trigger NEEDS_REVIEW to alert a human reviewer (security
review H-2 residual: defense-in-depth beyond the `--text` fix).
"""

from __future__ import annotations

from quill.policy import classify_sensitive_surface


def test_gitattributes_is_sensitive() -> None:
    assert classify_sensitive_surface(".gitattributes") == "gitconfig"


def test_gitattributes_nested() -> None:
    assert classify_sensitive_surface("subdir/.gitattributes") == "gitconfig"


def test_gitignore_is_sensitive() -> None:
    assert classify_sensitive_surface(".gitignore") == "gitconfig"


def test_gitignore_nested() -> None:
    assert classify_sensitive_surface("subdir/.gitignore") == "gitconfig"


def test_regular_file_not_gitconfig() -> None:
    assert classify_sensitive_surface("src/app.py") is None
