import datetime
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("dependency_policy", pathlib.Path(__file__).with_name("check-dependencies.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class DependencyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.today = datetime.date(2026, 9, 5)
        self.exception = dict(id="RUSTSEC-1", package="example", version="1.0", owner="maintainer",
                              expires=datetime.date(2026, 9, 6), reason="compatibility", migration="update parent")
        self.report = dict(vulnerabilities=dict(found=False, list=[]), warnings=dict(unmaintained=[dict(
            package=dict(name="example", version="1.0"), advisory=dict(id="RUSTSEC-1", informational="unmaintained"))]))

    def test_exact_unexpired_maintenance_exception(self):
        self.assertEqual(policy.check(self.report, [self.exception], self.today), [])

    def test_vulnerabilities_cannot_use_maintenance_exceptions(self):
        self.report["vulnerabilities"]["found"] = True
        self.assertTrue(policy.check(self.report, [self.exception], self.today))

    def test_expired_missing_and_changed_versions_fail(self):
        self.assertTrue(policy.check(self.report, [], self.today))
        self.assertTrue(policy.check(self.report, [self.exception], self.exception["expires"]))
        self.exception["version"] = "2.0"
        self.assertTrue(policy.check(self.report, [self.exception], self.today))

    def test_obsolete_exceptions_and_other_warning_categories_fail(self):
        self.report["warnings"] = {}
        self.assertTrue(policy.check(self.report, [self.exception], self.today))
        self.report["warnings"] = dict(yanked=[dict(package=dict(name="example", version="1.0"))])
        self.assertTrue(policy.check(self.report, [self.exception], self.today))


if __name__ == "__main__":
    unittest.main()
