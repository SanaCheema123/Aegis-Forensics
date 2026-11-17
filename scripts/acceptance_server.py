"""Browser acceptance server with temporary evidence/cases, never the user's histories."""
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.main import create_app
import uvicorn

if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='aegis-web-acceptance-') as directory:
        root = Path(directory)
        approved = root / 'approved'
        approved.mkdir()
        (approved / 'harmless.txt').write_text('Synthetic acceptance fixture; no executable content.')
        uvicorn.run(create_app(root, {'acceptance-fixture': approved}), host='127.0.0.1', port=8000, log_level='warning')
