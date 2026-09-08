import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("entitlements", Path(__file__).with_name("apple-exchange-entitlements.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.certificate = b"synthetic public test certificate"
        self.digest = hashlib.sha1(self.certificate).hexdigest()
        self.app = {
            "TeamIdentifier": ["TEAM"], "ApplicationIdentifierPrefix": ["PREFIX"],
            "Entitlements": {module.CAPABILITY: True},
        }
        self.extension = copy.deepcopy(self.app)
        self.extension["Entitlements"]["com.apple.application-identifier"] = "PREFIX.dev.factorseal.credentials"
        self.extension["DeveloperCertificates"] = [self.certificate]

    def validate(self):
        return module.extension_entitlements(self.app, self.extension, "dev.factorseal", self.digest)

    def test_extension_has_its_own_identity_and_no_vault_keychain_access(self):
        result = self.validate()
        self.assertEqual(result["com.apple.application-identifier"], "PREFIX.dev.factorseal.credentials")
        self.assertTrue(result["com.apple.security.app-sandbox"])
        self.assertNotIn("keychain-access-groups", result)

    def test_mismatched_team_prefix_identity_and_certificate_are_rejected(self):
        original = copy.deepcopy(self.extension)
        for key, value in [("TeamIdentifier", ["OTHER"]), ("ApplicationIdentifierPrefix", ["OTHER"]), ("DeveloperCertificates", [b"different certificate"])]:
            with self.subTest(key=key):
                self.extension = copy.deepcopy(original)
                self.extension[key] = value
                with self.assertRaises(ValueError):
                    self.validate()
        self.extension = original
        self.extension["Entitlements"]["com.apple.application-identifier"] = "PREFIX.dev.factorseal"
        with self.assertRaises(ValueError):
            self.validate()

    def test_capability_is_required_in_both_profiles(self):
        for profile in [self.app, self.extension]:
            with self.subTest(profile=profile):
                profile["Entitlements"][module.CAPABILITY] = False
                with self.assertRaises(ValueError):
                    self.validate()
                profile["Entitlements"][module.CAPABILITY] = True
