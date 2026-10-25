"""Compatibility shim for the report renderer.

The renderer lives at ``cutvertex/report_html.py``. This module exists only so that
code which imported ``report_html`` with the repository root on ``sys.path`` keeps
working, and it re-exports the real implementation rather than duplicating it.

Do not add logic here. Edit ``cutvertex/report_html.py``.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from cutvertex.report_html import render_html

__all__ = ["render_html"]
