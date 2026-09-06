# Password-manager transfer fixtures

These files can be selected in the import UI and are also exercised by
`src/transfer/fixture_tests.rs`. They contain public example/test credentials or
invented data, never a user's vault. Tests run offline:

```sh
devenv shell cargo test -p factorseal --no-default-features --features transfer --lib transfer::
```

## Sources

- `keepassxc/bitwarden_export.json`: unchanged from
  [KeePassXC's Bitwarden importer test data](https://github.com/keepassxreboot/keepassxc/blob/31a4c9ddd4cf81d68b64f9052f191fc5bb2d9126/tests/data/bitwarden_export.json).
  Commit: `31a4c9ddd4cf81d68b64f9052f191fc5bb2d9126`.
  SHA-256: `c5992873b5e30bd06417a81138600242bf7c92221cbe3ba4e7e456ebcde86d03`.
  Upstream attribution and terms are retained in `keepassxc/COPYING`;
  this fixture is redistributed under GPL-3.0 with `keepassxc/LICENSE.GPL-3`.
  Covers notes, cards, identities, logins, folders, multiple URLs, TOTP and custom
  fields. Round-trip equality checks FactorSeal's supported personal-secret
  fields, not the original JSON: IDs, dates, password history, URI match rules
  and custom-field type distinctions are not retained by the current model.
- `keepass-official.csv`: unchanged CSV extracted from KeePass's
  [official sample ZIP](https://keepass.info/help/download/FileSample_CSV.zip),
  linked in its [CSV format documentation](https://keepass.info/help/base/importexport.html#csv).
  Retrieved 2026-09-06. SHA-256:
  `3128410508742ae78fa25ccb8abb9f25d9c0c8eb2c13736eb9ed6b124ddf8abe`.
  Preserves the original UTF-8 BOM and CRLF line endings. Covers four entries,
  Unicode, backslash-escaped quotes/backslashes and multiline comments.
- `onepassword8.csv`: authored here with synthetic data using the nine columns
  in [1Password's export documentation](https://support.1password.com/export/)
  (checked 2026-09-06). This is a format-based fixture, not an actual app export.
  Covers commas, quotes, backslashes, Unicode, multiline notes, TOTP, tags,
  favorite/archive flags and a password-only row.

The KeePass sample exposed the difference between KeePass 1.x escaping and
ordinary CSV. Export tests check quoting/escaping explicitly; imports also
retain support for the unquoted header used by older FactorSeal exports.
Round trips do not establish acceptance by another application's UI.

The native encrypted archive fixture remains in `../keyring-v1.factorseal`.
