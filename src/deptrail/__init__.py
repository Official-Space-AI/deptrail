"""DepTrail — time-axis forensics for npm supply-chain incidents.

This constant is the single source of the version. ``pyproject.toml`` reads it
(``[tool.hatch.version]``) rather than restating it, because a second copy is a
copy that can disagree, and a report whose tool version cannot be trusted cannot
be reproduced by the person acting on it.
"""

__version__ = "0.1.0"
