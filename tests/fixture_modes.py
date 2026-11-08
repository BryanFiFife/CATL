"""Deterministic POSIX fixture modes for CATL tests.

src/catl/policy.py and src/catl/verifier.py deliberately refuse group- or
world-writable policy and postcondition-evidence paths. Hosts that default
to a user-private-group umask (Ubuntu: 002) otherwise make fixture files
group-writable (0664/0775) and the product fails them closed. Tests must
exercise the documented operating mode: 0644 files in 0700/0755 dirs.
"""
from __future__ import annotations
import os
from pathlib import Path


def umask_022(testcase) -> None:
    """Pin umask for files the fixture creates; restore on teardown."""
    old = os.umask(0o022)
    testcase.addCleanup(os.umask, old)


def trust_repo_fixture(path: Path) -> None:
    """Normalise modes of a pre-existing repo fixture.

    A fresh checkout inherits the cloning process's ambient umask, which on
    user-private-group distros leaves tracked files group-writable. The
    product's policy-trust checks are allowed to reject that. Contents are
    never modified.
    """
    p = Path(path)
    if p.is_dir():
        p.chmod(0o755)
        for child in p.rglob('*'):
            if child.is_symlink():
                continue
            child.chmod(0o755 if child.is_dir() else 0o644)
    else:
        p.chmod(0o644)
        if p.parent.is_dir() and not p.parent.is_symlink():
            p.parent.chmod(0o755)
