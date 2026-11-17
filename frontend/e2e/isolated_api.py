"""Temporary browser-test storage and alternate port; no forensic backend edits."""
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api.main import create_app
import uvicorn

if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='aegis-ui-acceptance-') as directory:
        root = Path(directory)
        folder = root / 'approved'
        folder.mkdir()
        (folder/'harmless.txt').write_text('Synthetic acceptance fixture; no executable content.')
        uvicorn.run(create_app(root, {'acceptance-fixture':folder}),host='127.0.0.1',port=8001,log_level='warning')
