"""Collision-safe storage for uploaded investigation evidence."""
from __future__ import annotations

from pathlib import Path


def evidence_id_for_file(directory: str | Path, path: str | Path) -> int:
    """Return the Evidence Vault ID for a stored file using the vault's ordering."""
    target = Path(path)
    files = sorted(
        (item for item in Path(directory).glob("*") if item.is_file()),
        key=lambda item: item.stat().st_mtime,
    )
    for evidence_id, item in enumerate(files, start=1):
        if item == target:
            return evidence_id
    raise FileNotFoundError(f"Evidence file {target.name} is not available in the Evidence Vault.")


def save_evidence_copy(directory: str | Path, name: str, data: bytes | memoryview) -> Path:
    """Save a basename-only evidence copy without replacing any existing file."""
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    original_name = Path(name).name or "evidence"
    original = Path(original_name)
    index = 0
    while True:
        candidate_name = (
            original_name
            if index == 0
            else f"{original.stem}_{index}{original.suffix}"
        )
        candidate = target_dir / candidate_name
        try:
            with candidate.open("xb") as destination:
                destination.write(data)
            return candidate
        except FileExistsError:
            index += 1
