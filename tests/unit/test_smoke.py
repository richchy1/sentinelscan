import importlib

import pytest

from sentinelscan import __version__
from sentinelscan.cli import main

MODULES = [
    "sentinelscan.cli",
    "sentinelscan.models",
    "sentinelscan.ports",
    "sentinelscan.services",
    "sentinelscan.http",
    "sentinelscan.tls",
    "sentinelscan.checks",
    "sentinelscan.scoring",
    "sentinelscan.scanner",
    "sentinelscan.reporter",
]


def test_package_imports() -> None:
    assert __version__ == "0.1.0"


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name: str) -> None:
    importlib.import_module(name)


@pytest.mark.parametrize("flag", ["--help", "--version"])
def test_cli_flags_exit_zero(flag: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["sentinelscan", flag])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0