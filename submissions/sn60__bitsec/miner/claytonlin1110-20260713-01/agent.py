from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from helpers.pipeline import run_agent


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    return run_agent(project_dir, inference_api)
