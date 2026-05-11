from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

ANALYSES_FILE = BASE_DIR / "data" / "analyses.json"
MODEL_FILE = BASE_DIR / "ml" / "verifyjobs_model.pkl"