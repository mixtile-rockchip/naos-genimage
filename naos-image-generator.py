#!/usr/bin/env python3
"""Run the generator directly from this source checkout."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))

from naos_image_generator.startup import entry_main

if __name__ == '__main__':
    raise SystemExit(entry_main())
