"""Offline consistency checks between requirements.txt and requirements.lock.txt.

P2 reproducibility gate: the committed lockfile pins every direct
requirement (and every transitive dependency) to an exact version with
sha256 hashes, so ``pip install --require-hashes -r requirements.lock.txt``
installs a reproducible dependency set without re-resolving the index.
These checks run offline on every CI leg and fail when the lockfile drifts
from requirements.txt or loses its hash coverage.
"""
from pathlib import Path
import unittest

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS_PATH = ROOT / "requirements.txt"
LOCK_PATH = ROOT / "requirements.lock.txt"


def _parse_requirements(path: Path) -> list[Requirement]:
    requirements = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        requirements.append(Requirement(line))
    return requirements


def _parse_lock(path: Path) -> dict[str, dict]:
    """Map canonical package name -> {"version", "hashes", "direct"}."""
    packages: dict[str, dict] = {}
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw[:1] in (" ", "\t"):
            stripped = raw.strip()
            if stripped.startswith("--hash=sha256:"):
                if current is not None:
                    packages[current]["hashes"] += 1
            elif stripped.startswith("#"):
                text = stripped.lstrip("#").strip()
                if current is not None and "-r requirements.txt" in text:
                    packages[current]["direct"] = True
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pin = stripped[:-1].rstrip() if stripped.endswith("\\") else stripped
        if "==" in pin:
            name, version = pin.split("==", 1)
            current = canonicalize_name(name.strip())
            packages[current] = {"version": version.strip(), "hashes": 0, "direct": False}
        else:
            current = None
    return packages


class DependencyLockTests(unittest.TestCase):
    def test_lock_file_exists_and_is_not_empty(self):
        self.assertTrue(LOCK_PATH.is_file(), "requirements.lock.txt is missing")
        self.assertTrue(LOCK_PATH.read_text(encoding="utf-8").strip())

    def test_every_direct_requirement_is_pinned_with_hashes(self):
        lock = _parse_lock(LOCK_PATH)
        requirements = _parse_requirements(REQUIREMENTS_PATH)
        self.assertTrue(requirements, "requirements.txt declared no requirements")
        for req in requirements:
            with self.subTest(package=req.name):
                key = canonicalize_name(req.name)
                self.assertIn(key, lock, f"{req.name} is missing from the lockfile")
                entry = lock[key]
                self.assertGreaterEqual(
                    entry["hashes"], 1, f"{req.name} has no sha256 hashes")
                self.assertTrue(
                    req.specifier.contains(Version(entry["version"]), prereleases=True),
                    f"{req.name}: locked {entry['version']} does not satisfy {req.specifier}",
                )

    def test_every_locked_package_carries_sha256_hashes(self):
        lock = _parse_lock(LOCK_PATH)
        self.assertTrue(lock, "requirements.lock.txt declares no packages")
        for name, entry in sorted(lock.items()):
            with self.subTest(package=name):
                self.assertGreaterEqual(
                    entry["hashes"], 1, f"{name} lacks sha256 hashes")
                self.assertRegex(entry["version"], r"^[A-Za-z0-9.]+$")

    def test_direct_packages_match_requirements_exactly(self):
        lock = _parse_lock(LOCK_PATH)
        requirements = _parse_requirements(REQUIREMENTS_PATH)
        locked_direct = {name for name, entry in lock.items() if entry["direct"]}
        declared = {canonicalize_name(req.name) for req in requirements}
        self.assertEqual(
            locked_direct, declared,
            f"direct dependency drift: lock={sorted(locked_direct)} "
            f"requirements={sorted(declared)}",
        )


if __name__ == "__main__":
    unittest.main()
