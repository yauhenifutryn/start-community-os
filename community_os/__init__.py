"""Local talent data-room pipeline for START Warsaw."""

from .event_definition import EventDefinition, EventDefinitionError, load_event_definition


__all__ = ("EventDefinition", "EventDefinitionError", "load_event_definition")
