"""Luma guest-list and status-supplement adapters."""

from .base import CsvAdapter


class LumaAdapter(CsvAdapter):
    """Strict adapter for observed Luma CSV export schemas."""
