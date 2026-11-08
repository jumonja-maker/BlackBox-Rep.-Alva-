"""Fail-closed network recovery for pinned Notepad++ release-only QA."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qa_decoder_apps as apps


class FakeResponse:
    def __init__(self, payload, url=apps.NPP_URL):
        self.payload = payload
        self.url = url
        self.position = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return self.url

    def read(self, count):
        data = self.payload[self.position:self.position + count]
        self.position += len(data)
        return data


class PinnedNotepadDownloadTests(unittest.TestCase):
    @contextmanager
    def output(self):
        with tempfile.TemporaryDirectory() as directory:
            yield Path(directory)

    @staticmethod
    def fake_extract(_archive, destination):
        destination.mkdir()
        (destination / "notepad++.exe").write_bytes(b"MZ" + b"fixed-test")

    def test_primary_transient_failure_recovers_from_exact_pinned_mirror(self):
        payload = b"pinned-notepad-release-bytes"
        digest = hashlib.sha256(payload).hexdigest()
        with self.output() as output, \
             patch.object(apps, "NPP_SHA256", digest), \
             patch.object(apps.urllib.request, "urlopen",
                          side_effect=[OSError("primary unreachable"),
                                       OSError("primary still unreachable"),
                                       FakeResponse(payload, apps.NPP_MIRROR_URL)]) as request, \
             patch.object(apps, "safe_extract", side_effect=self.fake_extract), \
             patch.object(apps.time, "sleep"):
            binary, proof = apps.pinned_notepad(output)
            self.assertTrue(binary.is_file())
            self.assertEqual(proof["archive_sha256"], digest)
            self.assertEqual(proof["source_url"], apps.NPP_MIRROR_URL)
            self.assertEqual((output / apps.NPP_ARCHIVE).read_bytes(), payload)
            self.assertFalse((output / (apps.NPP_ARCHIVE + ".partial")).exists())
            self.assertEqual(request.call_count, 3)

    def test_all_sources_unavailable_remains_not_executed(self):
        with self.output() as output, \
             patch.object(apps.urllib.request, "urlopen", side_effect=OSError("unavailable")) as request, \
             patch.object(apps.time, "sleep"):
            with self.assertRaisesRegex(apps.NotExecuted, "PINNED_NOTEPAD_DOWNLOAD_UNAVAILABLE"):
                apps.pinned_notepad(output)
            self.assertEqual(request.call_count, 4)
            self.assertFalse((output / apps.NPP_ARCHIVE).exists())

    def test_bad_sha_fails_hard_without_switching_source(self):
        with self.output() as output, \
             patch.object(apps.urllib.request, "urlopen", return_value=FakeResponse(b"wrong")) as request:
            with self.assertRaisesRegex(AssertionError, "PINNED_NOTEPAD_HASH_MISMATCH"):
                apps.pinned_notepad(output)
            self.assertEqual(request.call_count, 1)
            self.assertFalse((output / apps.NPP_ARCHIVE).exists())

    def test_http_downgrade_fails_hard(self):
        with self.output() as output, \
             patch.object(apps.urllib.request, "urlopen",
                          return_value=FakeResponse(b"data", "http://untrusted.example/test")) as request:
            with self.assertRaisesRegex(AssertionError, "PINNED_NOTEPAD_INSECURE_REDIRECT"):
                apps.pinned_notepad(output)
            self.assertEqual(request.call_count, 1)

    def test_oversized_response_fails_hard_without_fallback(self):
        with self.output() as output, \
             patch.object(apps, "MAX_DOWNLOAD", 3), \
             patch.object(apps.urllib.request, "urlopen", return_value=FakeResponse(b"1234")) as request:
            with self.assertRaisesRegex(AssertionError, "NOTEPAD_DOWNLOAD_BUDGET"):
                apps.pinned_notepad(output)
            self.assertEqual(request.call_count, 1)
            self.assertFalse((output / (apps.NPP_ARCHIVE + ".partial")).exists())


if __name__ == "__main__":
    unittest.main()
