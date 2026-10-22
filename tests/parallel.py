#!/usr/bin/env python3
"""Run the test suite in parallel shards: `python tests/parallel.py [shards]`.
Each gate test shells out to git and gitleaks, so one process is 80 s; four are 25 s.
Same as `python -m unittest discover tests`, run from the repo root, exit code included."""
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def names(suite):
    return [n for s in suite for n in names(s)] if isinstance(suite, unittest.TestSuite) else [suite.id()]


def main(shards=4):
    ids = names(unittest.TestLoader().discover(HERE))
    procs = [subprocess.Popen([sys.executable, "-m", "unittest", *ids[i::shards]], cwd=HERE,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT) for i in range(shards)]
    for p in procs:
        sys.stdout.write(p.communicate()[0].decode(errors="replace"))
    return max(p.returncode for p in procs)


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 4))
