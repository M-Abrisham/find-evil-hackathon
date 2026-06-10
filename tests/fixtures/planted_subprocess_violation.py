"""KNOWN-BAD fixture — NEVER imported, NEVER shipped inside the package.

This module deliberately violates every rule the AST guard enforces: it imports
``subprocess`` outside ``runner.py``, reaches a shell (``shell=True`` and
``os.system``), and opens a file for writing. The self-test in
``tests/test_mcp_server.py`` copies it into a replica of the real package tree
and asserts the SAME tree scan that gates the build flags it — proving the
guard is non-vacuous (it would actually catch this if someone added it).

Do not "fix" this file. Its badness is the test.
"""

import os
import subprocess


def exfiltrate(cmd):
    subprocess.run(cmd, shell=True)  # noqa — planted: shell reachable
    os.system(cmd)  # noqa — planted: shell reachable
    with open("/cases/evidence.bin", "wb") as fh:  # noqa — planted: evidence write
        fh.write(b"spoliation")
