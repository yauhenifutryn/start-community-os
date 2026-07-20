"""Shared public-text checks for stable internal personal-data identifiers."""

from __future__ import annotations

import re


STABLE_PSEUDONYM_RE = re.compile(
    r"(?:"
    r"pid:[a-z0-9._-]{1,32}:[0-9a-f]{64}"
    r"|psn_[a-z0-9][a-z0-9_:-]{1,127}"
    r"|colleague_[0-9a-f]{32}"
    r"|(?:person|member|project|team|class)_[0-9a-f]{24}"
    r"|(?:identity|team|classification)_[0-9a-f]{16}"
    r"|review_[0-9a-f]{20}"
    r"|evidence:[a-z][a-z0-9_]{0,31}:[0-9a-f]{64}"
    r"|source:application:[0-9a-f]{24}"
    r"|(?:actor|approval)_[0-9a-f]{8,64}"
    r")",
    re.IGNORECASE,
)
