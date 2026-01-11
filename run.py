#!/usr/bin/env python3
"""Quick runner script - use this without installing the package."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from strix_cli_claude.main import main

if __name__ == "__main__":
    main()
