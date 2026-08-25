"""Suite-wide guarantees about what a test may reach.

Since the walk began asking a remote which branches it has (#27), a test that
scans a real checkout — several pass ``--repo .``, which is this repository —
would run ``git ls-remote`` against GitHub. Four such calls were leaving on every
run of ``tests/test_registry.py`` alone: slow, offline-flaky, and a unit test
failing for a reason that has nothing to do with what it asserts.

``GIT_ALLOW_PROTOCOL`` is git's own answer. Set to ``file`` it permits the local
remotes the suite builds on purpose — bare paths and ``file://`` alike — and
refuses ``https`` and ``ssh`` in 15 ms with a plain error, which is exactly the
unreachable-remote branch the code is written to handle.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def no_network_git_transports(monkeypatch):
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")
