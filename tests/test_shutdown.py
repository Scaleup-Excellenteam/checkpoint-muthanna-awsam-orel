"""Exercise an idle server's interrupt handling in an isolated process."""

import subprocess
import sys
import tempfile
import textwrap
import unittest

from chat.config import PROJECT_ROOT


class ShutdownTests(unittest.TestCase):
    def test_idle_server_exits_on_pending_keyboard_interrupt(self):
        script = textwrap.dedent("""
            import _thread
            import os
            import sys
            import threading
            from pathlib import Path
            from chat.server import start_server

            os.environ['VIRUSTOTAL_API_KEY'] = ''
            root = Path(sys.argv[1])
            timer = threading.Timer(2, _thread.interrupt_main)
            timer.daemon = True
            timer.start()
            start_server(
                host='127.0.0.1', port=0, api_port=0,
                users_db=root / 'users.db', log_file=root / 'server.log',
            )
            assert not any(
                'serve_forever' in thread.name
                for thread in threading.enumerate()
            ), 'API thread is still running'
            print('SHUTDOWN_COMPLETE')
        """)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-u", "-c", script, directory],
                cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[STARTING] REST API:", result.stdout)
        self.assertIn("[STOPPING]", result.stdout)
        self.assertIn("SHUTDOWN_COMPLETE", result.stdout)
        self.assertNotIn("Traceback", result.stderr)
