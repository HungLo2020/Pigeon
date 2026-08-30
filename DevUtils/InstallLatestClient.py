#!/usr/bin/env python3
"""Download, verify, and install Pigeon's rolling latest desktop client."""

import sys

from install_latest import install


if __name__ == "__main__":
    try:
        raise SystemExit(install("pigeon-client", server=False))
    except RuntimeError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
