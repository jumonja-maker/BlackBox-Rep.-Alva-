"""Real subprocess I/O and cleanup for the decoder's detached launch mode.

The Windows CI run executes the Windows branch; POSIX results are not evidence
of Windows token or console behavior.
"""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from blackbox_core.optional_jobs import OwnedProcess


class DetachedDecoderProcessTests(unittest.TestCase):
    def test_detached_process_preserves_redirected_stdout_and_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "helper.log"
            with log.open("wb") as stream:
                owner = OwnedProcess([sys.executable, "-c",
                                      "import sys; print('OUT'); print('ERR', file=sys.stderr)"],
                                     stdout=stream, stderr=stream, detach_console=True)
                try:
                    self.assertEqual(owner.process.wait(timeout=20), 0)
                    self.assertEqual(owner.windows_creation_flags, 0x8 if os.name == "nt" else 0)
                finally:
                    owner.close(kill=True)
            self.assertEqual(set(log.read_text(encoding="utf-8").splitlines()), {"OUT", "ERR"})

    def test_detached_live_process_is_still_owned_and_killed(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "helper.log"
            with log.open("wb") as stream:
                owner = OwnedProcess([sys.executable, "-c",
                                      "import time; print('READY', flush=True); time.sleep(60)"],
                                     stdout=stream, stderr=stream, detach_console=True)
                try:
                    until = time.monotonic() + 20
                    while log.stat().st_size == 0 and owner.process.poll() is None and time.monotonic() < until:
                        time.sleep(.01)
                    self.assertIn("READY", log.read_text(encoding="utf-8"))
                    self.assertIsNone(owner.process.poll())
                finally:
                    owner.close(kill=True)
                self.assertIsNotNone(owner.process.poll())
                owner.close(kill=True)


if __name__ == "__main__":
    unittest.main()
