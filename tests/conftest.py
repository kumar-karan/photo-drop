import os
import sys
import shutil
from pathlib import Path

import pytest

TEST_DIR = Path(__file__).resolve().parent
APP_DIR = TEST_DIR.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))


@pytest.fixture(scope="session", autouse=True)
def configure_env(tmp_path_factory):
    base = tmp_path_factory.mktemp("photo_drop_test")
    token = "a" * 24  # >=12 chars
    owner = "b" * 24
    dest = base / "PhotoDrop"
    home = base / "home"
    os.environ["PHOTO_DROP_TOKEN"] = token
    os.environ["PHOTO_DROP_OWNER_TOKEN"] = owner
    os.environ["PHOTO_DROP_DIR"] = str(dest)
    os.environ["PHOTO_DROP_HOME"] = str(home)
    os.environ["PHOTO_DROP_RESERVE_BYTES"] = "1024"
    os.environ["PHOTO_DROP_MAX_FILE_BYTES"] = str(2 * 1024**3)
    os.environ["PHOTO_DROP_MAX_FILES"] = "500"
    yield


@pytest.fixture(autouse=True)
def ensure_dirs(tmp_path):
    # Ensure DEST/home exist by importing after env is set
    from server import DEST, HOME, BATCHES, LOGS

    DEST.mkdir(parents=True, exist_ok=True)
    HOME.mkdir(parents=True, exist_ok=True)
    BATCHES.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    # Clean stale parts
    for p in list(DEST.glob(".*.part")):
        p.unlink(missing_ok=True)
    for p in list(DEST.glob("*")):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    for p in list(BATCHES.iterdir()):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            p.unlink(missing_ok=True)
    yield
