from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "can_sentinel.db"

INTERFACE = "vcan0"

CALIBRATION_WINDOWS = 10
WINDOW_SECONDS = 1.0
HISTORY_POINTS = 120

# Conservative thresholds suitable for the synthetic lab traffic.
UNKNOWN_ID_THRESHOLD = 1
DLC_DEVIATION_THRESHOLD = 1
FLOOD_MIN_RATE = 50.0
REPLAY_RATIO_THRESHOLD = 0.70
