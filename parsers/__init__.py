"""
parsers/__init__.py
===================
Parsing layer for the Unified Email Threat Analysis Engine.

Every analyzer consumes the NormalizedEmail object produced by
`parsers.email_parser` — this prevents detectors from each doing their
own Gmail-response parsing.
"""