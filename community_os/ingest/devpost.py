"""Devpost adapters, intentionally unverified until a real export arrives."""

from .base import CsvAdapter


class DevpostAdapter(CsvAdapter):
    """Adapter for documented, not-yet-real-export-verified Devpost schemas."""
