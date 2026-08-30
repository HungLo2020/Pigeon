#!/usr/bin/env python3
"""Download, verify, and install Pigeon's rolling latest relay package."""

import sys

from install_latest import install


if __name__ == "__main__":
    try:
        raise SystemExit(install("pigeon-server", server=True))
    except RuntimeError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
