from __future__ import annotations

import os

DEFAULT_REGISTRY_URL = (
    "https://raw.githubusercontent.com/entrius/gittensor/test/"
    "gittensor/validator/weights/master_repositories.json"
)


def resolve_registry_url(explicit_url: str | None = None) -> str:
    if explicit_url:
        return explicit_url
    return os.environ.get("KATA_REGISTRY_URL", DEFAULT_REGISTRY_URL)
