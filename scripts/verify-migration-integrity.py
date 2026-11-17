"""Compare the pre-migration protected-file manifest without modifying any file."""
from pathlib import Path
import hashlib
import json
import sys

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root/'backups/react_fastapi_migration/protected_manifest.json').read_text())
changed = [name for name, digest in manifest.items() if not (root/name).is_file()
           or hashlib.sha256((root/name).read_bytes()).hexdigest() != digest]
print(json.dumps(dict(protected_files=len(manifest), changed=changed), indent=2))
sys.exit(bool(changed))
