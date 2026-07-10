"""Test isolation - make sure tests don't share global state under ~/.notari/.

Many of Notari's modules persist state to `$NOTARI_HOME/<file>` - approvals,
pin store, decay store, taint state, sessions index, etc. Without isolation,
test A leaves an approval in `~/.notari/approvals.json` that test B then
consumes (different test, different intent), producing flaky verdicts.

This autouse fixture points NOTARI_HOME at a per-test tmp directory so
every test gets a fresh, empty state dir. Tests that explicitly need to
touch the user's real `~/.notari/` should bypass this fixture by reading
the original env vars they want.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_notari_home(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Each test runs with a fresh NOTARI_HOME under tmp/. Auto-applied."""
    home = tmp_path_factory.mktemp("notari_home")
    monkeypatch.setenv("NOTARI_HOME", str(home))
    # Belt-and-suspenders: also clear per-file overrides so nothing the
    # parent shell set leaks into this test.
    for var in (
        "NOTARI_CONFIG",
        "NOTARI_LOG",
        "NOTARI_KEY",
        "NOTARI_DECAY_FILE",
        "NOTARI_TELEMETRY_PATH",
        "NOTARI_WATCH_PID",
        "NOTARI_SESSIONS",
        "NOTARI_TAINT_FILE",
        "NOTARI_PINS_FILE",
        "NOTARI_APPROVALS_FILE",
        "NOTARI_OVERNIGHT_FILE",
    ):
        monkeypatch.delenv(var, raising=False)
    yield home
