"""Universal BIOS installer for retrogaming platforms.

Self-contained script using only Python stdlib. Downloads missing BIOS files
from the retrobios repository and places them in the correct location for
the detected emulator platform.

Usage:
    python install.py
    python install.py --platform retroarch --dest ~/custom/bios
    python install.py --check
    python install.py --list-platforms
    python install.py --platform retroarch --system sony-playstation --region us
"""
