use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Android,
    Ios,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Factor {
    Password,
    Biometric,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
pub enum Format {
    #[serde(rename = "factorseal")]
    FactorSeal,
    #[serde(rename = "cxf-age")]
    CxfAge,
    #[serde(rename = "bitwarden-json")]
    BitwardenJson,
    #[serde(rename = "1password-csv")]
    OnePasswordCsv,
    #[serde(rename = "1password-1pux")]
    OnePasswordPux,
    #[serde(rename = "keepass-csv")]
    KeePassCsv,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum TransferKey {
    Passphrase(Secret),
    KeyFile(Secret),
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Site {
    Web(String),
    App(String),
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Lease {
    pub idle_seconds: u64,
    pub maximum_seconds: u64,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Start {
        directory: String,
        platform: Platform,
    },
    Status,
    Touch,
    Create {
        groups: Vec<Vec<Factor>>,
        password: Option<Secret>,
        lease: Lease,
    },
    Unlock {
        group: Vec<Factor>,
        password: Option<Secret>,
        lease: Lease,
    },
    Seal,
    RatePassword {
        password: Secret,
    },
    Items,
    Item {
        id: String,
    },
    Reveal {
        id: String,
        section: String,
        field: String,
    },
    Codes {
        id: String,
    },
    Template {
        kind: Kind,
    },
    Edit {
        id: String,
    },
    Save {
        item: Draft,
        version: Option<String>,
    },
    Favorite {
        id: String,
        favorite: bool,
    },
    Delete {
        id: String,
        version: String,
    },
    Restore,
    Generate {
        options: GeneratorOptions,
    },
    SetupKey {
        value: Secret,
        #[serde(default, rename = "same-as")]
        same_as: Option<Secret>,
    },
    SyncStart {
        name: String,
    },
    SyncStop,
    SyncView,
    SyncInvite {
        name: String,
    },
    SyncJoin {
        ticket: Secret,
        name: String,
    },
    SyncApprove {
        request: String,
    },
    SyncCancel,
    SyncRefresh,
    Classify {
        text: Secret,
    },
    Export {
        format: Format,
        key: Option<TransferKey>,
    },
    Import {
        format: Format,
        file: Secret,
        key: Option<TransferKey>,
    },
    ImportCommit {
        replace: bool,
    },
    ImportCancel,
    Logins {
        site: Site,
    },
    Fill {
        id: String,
        site: Site,
    },
    SaveLogin {
        site: Site,
        title: String,
        username: Secret,
        password: Secret,
    },
}

#[derive(Deserialize)]
#[serde(transparent)]
pub struct Secret(#[serde(deserialize_with = "zeroizing_string")] pub Zeroizing<String>);

fn zeroizing_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

pub struct Revealed(pub Zeroizing<String>);

impl Serialize for Revealed {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Response {
    Status(Status),
    Rating {
        score: u8,
        strength: Strength,
        acceptable: bool,
    },
    Items {
        items: Vec<Summary>,
    },
    Item {
        item: Item,
    },
    Value {
        value: Revealed,
    },
    Codes {
        codes: Vec<Code>,
    },
    Draft {
        item: Item,
    },
    Saved {
        id: String,
        version: String,
    },
    Deleted,
    Generated {
        password: Revealed,
        strength: Strength,
    },
    SetupKey {
        value: Option<Revealed>,
        issuer: Option<String>,
        account: Option<String>,
        same: bool,
    },
    Sync(SyncView),
    Scanned {
        scan: Scan,
    },
    File {
        name: String,
        data: Revealed,
    },
    ImportReview {
        items: usize,
        preserved: usize,
    },
    Imported {
        added: usize,
        replaced: usize,
        kept: usize,
        preserved: usize,
    },
    Logins {
        linked: Vec<Login>,
        others: Vec<Login>,
    },
    Credentials {
        username: Revealed,
        password: Revealed,
    },
    LoginSaved {
        id: String,
        change: LoginChange,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Status {
    pub vault: VaultState,
    pub groups: Vec<Vec<Factor>>,
    pub backend: Option<String>,
    pub paired: bool,
    pub idle_deadline: Option<u64>,
    pub absolute_deadline: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultState {
    Absent,
    Sealed,
    Unsealed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strength {
    Weak,
    Good,
    Strong,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    ApiCredential,
    Passport,
    BankAccount,
    Document,
    Generic,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldType {
    Text,
    Concealed,
    Url,
    Email,
    Phone,
    Date,
    MonthYear,
    Totp,
    Multiline,
    Boolean,
    CardNumber,
    SshKey,
    Address,
    Reference,
    Unknown,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Summary {
    pub id: String,
    pub title: String,
    pub kind: Kind,
    pub username: Option<String>,
    pub website: Option<String>,
    pub updated_at: Option<u64>,
    pub favorite: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Login {
    pub id: String,
    pub title: String,
    pub username: String,
}

impl Drop for Login {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoginChange {
    Added,
    Updated,
    Unchanged,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Item {
    pub id: String,
    pub kind: Kind,
    pub title: String,
    pub favorite: bool,
    pub notes: Option<String>,
    pub notes_filled: bool,
    pub website: Option<String>,
    pub sections: Vec<Section>,
    pub version: Option<String>,
}

impl Drop for Item {
    fn drop(&mut self) {
        self.title.zeroize();
        self.notes.zeroize();
        self.website.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Section {
    pub id: String,
    pub label: String,
    pub fields: Vec<Field>,
}

impl Drop for Section {
    fn drop(&mut self) {
        self.label.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Field {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: FieldType,
    pub concealed: bool,
    #[serde(default)]
    pub filled: bool,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    #[serde(default)]
    pub link: Option<String>,
}

impl Drop for Field {
    fn drop(&mut self) {
        self.label.zeroize();
        self.link.zeroize();
        if let Some(value) = &mut self.value {
            factorseal::personal::zeroize_json_strings(value);
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Draft {
    pub id: String,
    pub kind: Kind,
    pub title: String,
    pub favorite: bool,
    pub notes: Option<String>,
    pub sections: Vec<Section>,
}

impl Drop for Draft {
    fn drop(&mut self) {
        self.title.zeroize();
        self.notes.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Code {
    pub section: String,
    pub field: String,
    pub value: Revealed,
    pub period: u64,
    pub remaining: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct GeneratorOptions {
    pub style: GeneratorStyle,
    pub length: u8,
    pub words: u8,
    pub digits: bool,
    pub symbols: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeneratorStyle {
    Random,
    Words,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SyncView {
    pub running: bool,
    pub paired: bool,
    pub devices: Vec<Device>,
    pub reachable: usize,
    pub last_exchange: Option<u64>,
    pub pending: usize,
    pub conflicts: usize,
    pub readers: usize,
    pub invitation: Option<Invitation>,
    pub review: Option<Review>,
    pub joining: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Device {
    pub name: String,
    pub local: bool,
    pub reader: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Invitation {
    pub ticket: Revealed,
    pub modules: Vec<Vec<bool>>,
    pub expires: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Review {
    pub request: String,
    pub code: String,
    pub devices: Vec<Device>,
    pub verified: bool,
    pub waiting: bool,
    pub approved_here: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    NotStarted,
    Absent,
    Exists,
    Sealed,
    PasswordRequired,
    PasswordRejected,
    WeakPassword,
    Cancelled,
    Denied,
    UiUnavailable,
    SessionLocked,
    CredentialInvalidated,
    HardwareUnavailable,
    PolicyUnsupported,
    NotFound,
    Changed,
    Conflict,
    Invalid,
    NothingToRestore,
    Sync,
    Failed,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Scan {
    Nothing,
    Pairing {
        ticket: Revealed,
    },
    OneTimePassword {
        value: Revealed,
        issuer: Option<String>,
        account: Option<String>,
    },
    Unsupported,
}
