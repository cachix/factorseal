import pathlib
import runpy
import unittest

dependency_drift = runpy.run_path(
    str(pathlib.Path(__file__).with_name("check-fuzz-lock.py"))
)["dependency_drift"]


class FuzzLockTests(unittest.TestCase):
    def test_registry_copy_cannot_replace_patched_dependency(self):
        product = [{"name": "automerge", "version": "0.11.0", "source": "git+fork#fixed"}]
        fuzz = [{"name": "automerge", "version": "0.11.0", "source": "registry+crates.io"}]
        self.assertTrue(dependency_drift(product, fuzz))

    def test_different_git_revision_is_rejected(self):
        product = [{"name": "automerge", "version": "0.11.0", "source": "git+fork#fixed"}]
        fuzz = [{"name": "automerge", "version": "0.11.0", "source": "git+fork#old"}]
        self.assertTrue(dependency_drift(product, fuzz))

    def test_exact_matches_and_fuzz_only_packages_are_allowed(self):
        shared = {"name": "automerge", "version": "0.11.0", "source": "git+fork#fixed"}
        self.assertEqual(dependency_drift([shared], [shared, {"name": "libfuzzer-sys", "version": "0.4.13"}]), [])
