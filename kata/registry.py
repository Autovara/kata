from __future__ import annotations

import json
from typing import Any
from urllib.request import urlopen


def load_registry(url: str) -> dict[str, Any]:
    with urlopen(url, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))
