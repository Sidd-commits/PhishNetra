import sys
from pathlib import Path

# Ensure services/ml root is on sys.path
ml_dir = Path(__file__).resolve().parent
if str(ml_dir) not in sys.path:
    sys.path.insert(0, str(ml_dir))
