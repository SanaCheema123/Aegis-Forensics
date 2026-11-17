import tempfile
import unittest
from pathlib import Path

from modules.evidence_storage import save_evidence_copy


class EvidenceStorageTests(unittest.TestCase):
    def test_same_name_upload_never_overwrites_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            original = save_evidence_copy(directory, "evidence.txt", b"original")
            second = save_evidence_copy(directory, "evidence.txt", memoryview(b"second"))

            self.assertEqual(original.name, "evidence.txt")
            self.assertEqual(second.name, "evidence_1.txt")
            self.assertEqual(original.read_bytes(), b"original")
            self.assertEqual(second.read_bytes(), b"second")


if __name__ == "__main__":
    unittest.main()
