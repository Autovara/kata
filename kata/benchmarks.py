from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

BENCHMARKS_ROOT_ENV = "KATA_BENCHMARKS_ROOT"
REGISTRY_MARKER_FILENAME = "kata-benchmark-registry.json"
DEFAULT_BENCHMARKS_DIR = "benchmarks"
KATA_REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class BenchmarkRegistry:
    root: Path
    benchmarks_dir: Path
    marker_path: Path
    schema_version: int
    registry_name: str | None
    active_repo_packs: tuple[str, ...]
    default_repo_pack: str | None


def resolve_benchmark_registry(
    explicit_root: str | None = None,
    *,
    require_exists: bool = True,
) -> BenchmarkRegistry:
    configured_root = explicit_root or os.environ.get(BENCHMARKS_ROOT_ENV)
    if configured_root:
        return load_registry_from_reference(configured_root, require_exists=require_exists)

    discovered_root = discover_registry_root()
    if discovered_root is None:
        raise FileNotFoundError(
            "Could not find a Kata benchmark registry. "
            f"Set {BENCHMARKS_ROOT_ENV} or add {REGISTRY_MARKER_FILENAME} to the "
            "benchmark registry repo."
        )
    return load_registry_from_reference(str(discovered_root), require_exists=require_exists)


def resolve_benchmarks_root(
    explicit_root: str | None = None,
    *,
    require_exists: bool = True,
) -> Path:
    return resolve_benchmark_registry(
        explicit_root=explicit_root,
        require_exists=require_exists,
    ).benchmarks_dir


def resolve_eval_pack_path(
    eval_pack_ref: str,
    *,
    benchmarks_root: str | None = None,
    require_exists: bool = True,
) -> Path:
    direct_path = Path(eval_pack_ref).expanduser()
    if direct_path.exists():
        return direct_path.resolve()

    if looks_like_path(eval_pack_ref):
        raise FileNotFoundError(f"Eval pack path does not exist: {direct_path}")

    pack_path = (
        resolve_benchmarks_root(benchmarks_root, require_exists=require_exists) / eval_pack_ref
    )
    if require_exists and not pack_path.exists():
        raise FileNotFoundError(
            "Could not find the eval pack in the benchmark registry: "
            f"{pack_path}. Pass a filesystem path or a pack id under the "
            f"benchmark root configured by {BENCHMARKS_ROOT_ENV}."
        )
    return pack_path.resolve()


def ensure_active_repo_pack(
    repo_pack: str,
    *,
    benchmarks_root: str | None = None,
) -> None:
    registry = resolve_benchmark_registry(benchmarks_root, require_exists=True)
    if not registry.active_repo_packs:
        return
    if repo_pack in registry.active_repo_packs:
        return
    allowed = ", ".join(registry.active_repo_packs)
    raise ValueError(
        "Repo pack is not active in this Kata registry: "
        f"{repo_pack}. Active repo packs: {allowed}"
    )


def render_benchmark_registry(registry: BenchmarkRegistry) -> str:
    lines = [
        f"Registry root: {registry.root}",
        f"Benchmarks dir: {registry.benchmarks_dir}",
        f"Registry marker: {registry.marker_path}",
        f"Schema version: {registry.schema_version}",
        f"Registry name: {registry.registry_name or 'unknown'}",
    ]
    if registry.active_repo_packs:
        lines.append("Active repo packs:")
        lines.extend(f"- {repo_pack}" for repo_pack in registry.active_repo_packs)
    else:
        lines.append("Active repo packs: all packs allowed")
    if registry.default_repo_pack:
        lines.append(f"Default repo pack: {registry.default_repo_pack}")
    return "\n".join(lines)


def load_registry_from_reference(
    reference: str,
    *,
    require_exists: bool,
) -> BenchmarkRegistry:
    input_path = Path(reference).expanduser()
    candidate_root, explicit_benchmarks_dir = normalize_registry_reference(
        input_path,
        require_exists=require_exists,
    )
    marker_path = resolve_registry_marker(candidate_root)

    if require_exists and marker_path is None:
        raise FileNotFoundError(
            "Benchmark registry marker not found. Expected: "
            f"{candidate_root / REGISTRY_MARKER_FILENAME}. "
            f"Add {REGISTRY_MARKER_FILENAME} to the registry repo "
            f"or set {BENCHMARKS_ROOT_ENV} to a valid registry root."
        )
    if marker_path is None:
        marker_path = candidate_root / REGISTRY_MARKER_FILENAME

    payload = read_registry_payload(marker_path)
    if explicit_benchmarks_dir is not None:
        benchmarks_dir = explicit_benchmarks_dir.resolve()
    else:
        benchmarks_dir_name = payload.get("benchmarks_dir", DEFAULT_BENCHMARKS_DIR)
        if not isinstance(benchmarks_dir_name, str) or not benchmarks_dir_name.strip():
            raise ValueError(
                f"Invalid `benchmarks_dir` in {marker_path}. Expected a non-empty string."
            )
        benchmarks_dir = (candidate_root / benchmarks_dir_name).resolve()
    if require_exists and not benchmarks_dir.exists():
        raise FileNotFoundError(
            "Benchmark registry is missing its benchmarks directory: "
            f"{benchmarks_dir}"
        )

    schema_version = payload.get("schema_version", 1)
    if not isinstance(schema_version, int):
        raise ValueError(f"Invalid `schema_version` in {marker_path}. Expected an integer.")

    registry_name = payload.get("registry_name")
    if registry_name is not None and not isinstance(registry_name, str):
        raise ValueError(f"Invalid `registry_name` in {marker_path}. Expected a string.")

    active_repo_packs = normalize_repo_pack_list(
        payload.get("active_repo_packs"),
        marker_path,
        field_name="active_repo_packs",
    )
    default_repo_pack = payload.get("default_repo_pack")
    if default_repo_pack is not None:
        if not isinstance(default_repo_pack, str) or not default_repo_pack.strip():
            raise ValueError(
                f"Invalid `default_repo_pack` in {marker_path}. Expected a non-empty string."
            )
        default_repo_pack = default_repo_pack.strip()
        if active_repo_packs and default_repo_pack not in active_repo_packs:
            raise ValueError(
                f"Invalid `default_repo_pack` in {marker_path}. "
                "It must also appear in `active_repo_packs`."
            )

    return BenchmarkRegistry(
        root=candidate_root.resolve(),
        benchmarks_dir=benchmarks_dir,
        marker_path=marker_path.resolve(),
        schema_version=schema_version,
        registry_name=registry_name,
        active_repo_packs=active_repo_packs,
        default_repo_pack=default_repo_pack,
    )


def normalize_registry_reference(
    path: Path,
    *,
    require_exists: bool,
) -> tuple[Path, Path | None]:
    expanded = path.expanduser()
    if expanded.is_file():
        if expanded.name != REGISTRY_MARKER_FILENAME:
            raise ValueError(
                "Benchmark registry reference must be a registry root, benchmarks "
                f"directory, or {REGISTRY_MARKER_FILENAME}."
            )
        return expanded.parent, None

    if resolve_registry_marker(expanded) is not None:
        return expanded, None

    if expanded.name == DEFAULT_BENCHMARKS_DIR and resolve_registry_marker(expanded.parent):
        return expanded.parent, expanded

    if expanded.name == DEFAULT_BENCHMARKS_DIR and not require_exists:
        return expanded.parent, expanded

    return expanded, None


def discover_registry_root() -> Path | None:
    for base_dir in discovery_bases():
        found = discover_registry_under(base_dir)
        if found is not None:
            return found
    return None


def discovery_bases() -> list[Path]:
    cwd = Path.cwd().resolve()
    candidates = [
        cwd,
        cwd.parent,
        KATA_REPO_ROOT,
        KATA_REPO_ROOT.parent,
    ]
    return unique_paths(candidates)


def discover_registry_under(base_dir: Path) -> Path | None:
    if not base_dir.exists() or not base_dir.is_dir():
        return None
    if resolve_registry_marker(base_dir) is not None:
        return base_dir

    try:
        children = sorted(base_dir.iterdir(), key=lambda entry: entry.name)
    except OSError:
        return None

    for child in children:
        if child.is_dir() and resolve_registry_marker(child) is not None:
            return child
    return None


def resolve_registry_marker(root: Path) -> Path | None:
    marker_path = root / REGISTRY_MARKER_FILENAME
    if marker_path.exists():
        return marker_path
    return None


def read_registry_payload(marker_path: Path) -> dict[str, object]:
    if not marker_path.exists():
        return {"schema_version": 1, "benchmarks_dir": DEFAULT_BENCHMARKS_DIR}

    payload = json.loads(marker_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Registry marker must contain a JSON object: {marker_path}")
    return payload


def normalize_repo_pack_list(
    raw_value: object,
    marker_path: Path,
    *,
    field_name: str,
) -> tuple[str, ...]:
    if raw_value is None:
        return ()
    if not isinstance(raw_value, list):
        raise ValueError(f"Invalid `{field_name}` in {marker_path}. Expected an array of strings.")

    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"Invalid `{field_name}` in {marker_path}. Expected non-empty strings."
            )
        value = item.strip()
        if value in seen:
            continue
        normalized.append(value)
        seen.add(value)
    return tuple(normalized)


def unique_paths(paths: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        unique.append(path)
        seen.add(key)
    return unique


def looks_like_path(value: str) -> bool:
    return (
        value.startswith(".")
        or value.startswith("~")
        or value.startswith("/")
        or "/" in value
        or "\\" in value
    )
