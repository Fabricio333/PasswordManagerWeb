import sys
from pathlib import Path

# Ensure the package root is on sys.path for test imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
