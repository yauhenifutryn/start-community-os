"""Shared canonical-model vocabulary.

The pipeline intentionally keeps persistence in SQLite. These enums give later
stages one typed vocabulary without introducing an ORM or another dependency.
"""

from enum import StrEnum


class PersonState(StrEnum):
    ACTIVE = "active"
    GHOST = "ghost"


class IdentityType(StrEnum):
    EMAIL = "email"
    GITHUB = "github"
    LINKEDIN = "linkedin"


class IntroOutcome(StrEnum):
    NONE = "none"
    INTERVIEW = "interview"
    HIRE = "hire"
    INVESTMENT = "investment"
