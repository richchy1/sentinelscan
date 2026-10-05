"""SentinelScan command-line interface."""

import argparse

from sentinelscan import __version__


def main() -> None:
    """Run the SentinelScan CLI."""
    parser = argparse.ArgumentParser(
        prog="sentinelscan",
        description="SentinelScan security scanning toolkit.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
    )

    parser.parse_args()


if __name__ == "__main__":
    main()
