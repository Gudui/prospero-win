# SPDX-License-Identifier: LGPL-2.1-or-later
import unittest
from pathlib import Path
import sys
import tempfile
import hashlib
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.fetch_lapy_helper import stage_local_helper, validate_helper_manifest, verify_pinned_elf


class PinnedElfTests(unittest.TestCase):
    def test_accepts_the_pinned_bytes_in_either_case(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "lapy.elf"
            elf.write_bytes(b"pinned helper")
            digest = hashlib.sha256(b"pinned helper").hexdigest()
            verify_pinned_elf(elf, digest)
            verify_pinned_elf(elf, digest.upper())

    def test_rejects_other_bytes_and_names_both_digests(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "lapy.elf"
            elf.write_bytes(b"newer helper")
            pinned = hashlib.sha256(b"pinned helper").hexdigest()
            actual = hashlib.sha256(b"newer helper").hexdigest()
            with self.assertRaisesRegex(ValueError, f"{actual}.*{pinned}"):
                verify_pinned_elf(elf, pinned)

    def test_rejects_an_empty_download(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "lapy.elf"
            elf.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "the pin is"):
                verify_pinned_elf(elf, hashlib.sha256(b"pinned helper").hexdigest())


class HelperManifestTests(unittest.TestCase):
    def test_requires_exact_helper_identity_digests_and_retry_feature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / "lapy.elf"
            protocol = root / "lapy_elevation_protocol.h"
            elf.write_bytes(b"tested helper")
            protocol.write_bytes(b"wire ABI")
            manifest = {
                "mode": "elf-helper",
                "target_title": "PPSA99995",
                "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
                "protocol_sha256": hashlib.sha256(protocol.read_bytes()).hexdigest(),
                "features": ["root_layout_probe_retry"],
            }
            validate_helper_manifest(manifest, elf, protocol, "PPSA99995")
            with self.assertRaisesRegex(ValueError, "root_layout_probe_retry"):
                validate_helper_manifest({**manifest, "features": []}, elf,
                                         protocol, "PPSA99995")
            with self.assertRaisesRegex(ValueError, "manifest, title or digest"):
                validate_helper_manifest({**manifest, "target_title": "PPSA00000"},
                                         elf, protocol, "PPSA99995")


class LocalHelperTests(unittest.TestCase):
    def test_local_stage_preserves_bytes_and_records_local_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, out = root / "source", root / "out"
            source.mkdir()
            (source / "lapy.elf").write_bytes(b"qualified helper")
            manifest = b'{"target_title":"PPSA00000"}\n'
            (source / "lapy-manifest.json").write_bytes(manifest)
            digest = hashlib.sha256(b"qualified helper").hexdigest()
            stage_local_helper(source, out, digest)
            self.assertEqual((out / "lapy.elf").read_bytes(), b"qualified helper")
            self.assertEqual((out / "lapy-manifest.json").read_bytes(), manifest)
            metadata = json.loads((out / "release.json").read_text())
            self.assertEqual(metadata["source_kind"], "local-pinned-helper")
            self.assertEqual(metadata["elf_sha256"], digest)
            self.assertIsNone(metadata["tag_name"])

    def test_local_stage_rejects_wrong_hash_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "lapy.elf").write_bytes(b"changed helper")
            with self.assertRaisesRegex(ValueError, "the pin is"):
                stage_local_helper(root, root / "out", "0" * 64)
            self.assertFalse((root / "out").exists())

    def test_local_stage_requires_parseable_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "lapy.elf").write_bytes(b"helper")
            (root / "lapy-manifest.json").write_text("invalid")
            with self.assertRaises(ValueError):
                stage_local_helper(root, root / "out", hashlib.sha256(b"helper").hexdigest())
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
