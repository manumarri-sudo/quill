"""Allow `python -m notari ...` (and the daemon spawn path).

The daemon helper in watch.py spawns
    [sys.executable, "-m", "notari", "watch", "--daemon-child", ...]
so the same Python interpreter that installed the package runs the
detached dashboard process. This module just delegates to the typer
app defined in cli.py.
"""

from notari.cli import app

if __name__ == "__main__":
    app()
