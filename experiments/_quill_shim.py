"""Compat shim: import Quill primitives whether the package is named ``quill``
(post-rename) or ``janus_mcp`` (pre-rename). The article release will be
``quill``. This shim lets the harness run during the transition.

We always re-export the canonical names so the rest of experiments/* can do::

    from _quill_shim import AuditLog, SessionTree, Scope, SessionIntent, ...
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the in-tree src/ importable without an editable install.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

try:  # the post-rename world
    from quill.policy import Risk, Scope, SessionIntent, classify  # type: ignore
    from quill.audit import AuditLog, verify_chain  # type: ignore
    from quill.session import SessionTree  # type: ignore
    from quill.prompt import Prompter  # type: ignore
    from quill.tree import render_tree_static, render_tree_live  # type: ignore
    from quill.errors import (  # type: ignore
        ScopeViolation,
        HumanDeclined,
        ConfirmationMismatch,
        PolicyDenied,
    )

    _PKG = "quill"
except ImportError:
    from janus_mcp.policy import Risk, Scope, SessionIntent, classify  # type: ignore
    from janus_mcp.audit import AuditLog, verify_chain  # type: ignore
    from janus_mcp.session import SessionTree  # type: ignore
    from janus_mcp.prompt import Prompter  # type: ignore
    from janus_mcp.tree import render_tree_static, render_tree_live  # type: ignore
    from janus_mcp.errors import (  # type: ignore
        ScopeViolation,
        HumanDeclined,
        ConfirmationMismatch,
        PolicyDenied,
    )

    _PKG = "janus_mcp"

__all__ = [
    "Risk",
    "Scope",
    "SessionIntent",
    "classify",
    "AuditLog",
    "verify_chain",
    "SessionTree",
    "Prompter",
    "render_tree_static",
    "render_tree_live",
    "ScopeViolation",
    "HumanDeclined",
    "ConfirmationMismatch",
    "PolicyDenied",
    "_PKG",
]
