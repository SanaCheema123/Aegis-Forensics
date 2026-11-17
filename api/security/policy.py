import re
from pathlib import Path


class ServiceError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def case_identifier(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value) or ".." in value:
        raise ServiceError("Invalid case identifier.", 422)
    return value


def safe_filename(value):
    if (not value or len(value) > 180 or value != Path(value).name
            or re.search(r'[<>:"/\\|?*\x00-\x1f]', value) or value.endswith((".", " "))
            or value.split('.')[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}):
        raise ServiceError("Use a plain, valid filename without a path.", 422)
    return value


def unlinked_path(path, parent):
    """Reject symlinks/junctions as well as paths leaving the intended store."""
    path, parent = Path(path), Path(parent)
    if not path.resolve().is_relative_to(parent.resolve()):
        raise ServiceError("Evidence is outside the approved store.", 403)
    for item in [path, *path.parents]:
        if item.is_symlink() or (item.exists() and getattr(item.stat(), 'st_file_attributes', 0) & 0x400):
            raise ServiceError("Linked files and directories are not supported.", 403)
        if item == parent:
            break
    return path
