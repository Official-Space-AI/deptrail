"""DepTrail — time-axis forensics for npm supply-chain incidents.

This constant is the single source of the version. ``pyproject.toml`` reads it
(``[tool.hatch.version]``) rather than restating it, because a second copy is a
copy that can disagree about what code produced a given answer.

It currently reaches ``deptrail --version`` and nothing else: no report names the
version that wrote it, so a responder holding a report still cannot tell. That is
#53, not something this constant fixes on its own.
"""

__version__ = "0.1.1"
