"""
Three-pass Jolt patch pipeline.

Jolt currently does not require snapshot-side source edits for the tracked benchmark commit,
but we keep the same install-time pipeline shape as the other zkVMs so version-specific
patches can be added without changing the CLI contract later.
"""

