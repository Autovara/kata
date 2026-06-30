from __future__ import annotations

import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class RepositoryContext:
    root: Path
    display_name: str
    full_name: str | None
    source_url: str | None


@contextmanager
def resolve_repository(repo_ref: str):
    source_ref, git_ref = split_repo_ref(repo_ref)

    if is_github_url(source_ref):
        with tempfile.TemporaryDirectory(prefix="kata-repo-") as tmpdir:
            root = clone_repo(source_ref, Path(tmpdir), git_ref)
            full_name = github_full_name(source_ref)
            yield RepositoryContext(
                root=root,
                display_name=full_name.split("/")[-1],
                full_name=full_name,
                source_url=repo_ref,
            )
        return

    root = Path(source_ref).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {source_ref}")

    if git_ref is not None:
        with tempfile.TemporaryDirectory(prefix="kata-repo-") as tmpdir:
            detached_root = clone_repo(str(root), Path(tmpdir), git_ref)
            full_name = infer_full_name_from_git_remote(detached_root)
            yield RepositoryContext(
                root=detached_root,
                display_name=root.name,
                full_name=full_name,
                source_url=repo_ref,
            )
        return

    full_name = infer_full_name_from_git_remote(root)
    yield RepositoryContext(
        root=root,
        display_name=root.name,
        full_name=full_name,
        source_url=None,
    )


def is_github_url(repo_ref: str) -> bool:
    parsed = urlparse(repo_ref)
    return parsed.scheme in {"http", "https"} and parsed.netloc == "github.com"


def github_full_name(repo_ref: str) -> str:
    parsed = urlparse(repo_ref)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ValueError(f"Unsupported GitHub repo URL: {repo_ref}")
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"{parts[0]}/{repo}"


def clone_repo(repo_ref: str, tmpdir: Path, git_ref: str | None = None) -> Path:
    target = tmpdir / "repo"
    clone_command = ["git", "clone", repo_ref, str(target)]
    if git_ref is None:
        clone_command = ["git", "clone", "--depth", "1", repo_ref, str(target)]
    subprocess.run(clone_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if git_ref is not None:
        subprocess.run(
            ["git", "-C", str(target), "checkout", git_ref],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return target


def split_repo_ref(repo_ref: str) -> tuple[str, str | None]:
    base, separator, git_ref = repo_ref.strip().rpartition("@")
    if not separator or not base or not git_ref:
        return repo_ref.strip(), None
    if is_github_url(base):
        return base, git_ref
    if Path(base).expanduser().exists():
        return base, git_ref
    return repo_ref.strip(), None


def infer_full_name_from_git_remote(root: Path) -> str | None:
    git_dir = root / ".git"
    if not git_dir.exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        return None
    origin = result.stdout.strip()
    if origin.startswith("git@github.com:"):
        path = origin.removeprefix("git@github.com:").removesuffix(".git")
        return path
    if is_github_url(origin):
        return github_full_name(origin)
    return None
