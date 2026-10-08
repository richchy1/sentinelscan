"""Shared pytest configuration."""

from pathlib import Path

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark tests by directory so ``-m unit`` / ``-m integration`` work."""
    for item in items:
        parts = Path(str(item.fspath)).parts
        if "integration" in parts:
            item.add_marker(pytest.mark.integration)
        elif "unit" in parts:
            item.add_marker(pytest.mark.unit)
