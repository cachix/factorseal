package com.cachix.factorseal.core

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
enum class Platform {
    @SerialName("android")
    Android,

    @SerialName("ios")
    Ios,
}

@Serializable
enum class Factor {
    @SerialName("password")
    Password,

    @SerialName("biometric")
    Biometric,
}

@Serializable
data class Lease(
    val idleSeconds: Long,
    val maximumSeconds: Long,
)

@Serializable
enum class Kind {
    @SerialName("login")
    Login,

    @SerialName("secure-note")
    SecureNote,

    @SerialName("card")
    Card,

    @SerialName("identity")
    Identity,

    @SerialName("ssh-key")
    SshKey,

    @SerialName("api-credential")
    ApiCredential,

    @SerialName("passport")
    Passport,

    @SerialName("bank-account")
    BankAccount,

    @SerialName("document")
    Document,

    @SerialName("generic")
    Generic,
}

@Serializable
enum class FieldType {
    @SerialName("text")
    Text,

    @SerialName("concealed")
    Concealed,

    @SerialName("url")
    Url,

    @SerialName("email")
    Email,

    @SerialName("phone")
    Phone,

    @SerialName("date")
    Date,

    @SerialName("month-year")
    MonthYear,

    @SerialName("totp")
    Totp,

    @SerialName("multiline")
    Multiline,

    @SerialName("boolean")
    Boolean,

    @SerialName("card-number")
    CardNumber,

    @SerialName("ssh-key")
    SshKey,

    @SerialName("address")
    Address,

    @SerialName("reference")
    Reference,

    @SerialName("unknown")
    Unknown,
}

@Serializable
enum class Strength {
    @SerialName("weak")
    Weak,

    @SerialName("good")
    Good,

    @SerialName("strong")
    Strong,
}

@Serializable
enum class GeneratorStyle {
    @SerialName("random")
    Random,

    @SerialName("words")
    Words,
}

@Serializable
data class GeneratorOptions(
    val style: GeneratorStyle = GeneratorStyle.Words,
    val length: Int = 20,
    val words: Int = 12,
    val digits: Boolean = true,
    val symbols: Boolean = true,
)

@Serializable
data class Field(
    val id: String,
    val label: String,
    val type: FieldType,
    val concealed: Boolean,
    val filled: Boolean = false,
    val value: JsonElement? = null,
    val link: String? = null,
)

@Serializable
data class Section(
    val id: String,
    val label: String,
    val fields: List<Field>,
)

@Serializable
data class Item(
    val id: String,
    val kind: Kind,
    val title: String,
    val favorite: Boolean,
    val notes: String? = null,
    val notesFilled: Boolean = false,
    val website: String? = null,
    val sections: List<Section>,
    val version: String? = null,
)

@Serializable
data class Draft(
    val id: String,
    val kind: Kind,
    val title: String,
    val favorite: Boolean,
    val notes: String?,
    val sections: List<Section>,
)

@Serializable
data class Summary(
    val id: String,
    val title: String,
    val kind: Kind,
    val username: String? = null,
    val website: String? = null,
    val updatedAt: Long? = null,
    val favorite: Boolean = false,
)

@Serializable
data class Code(
    val section: String,
    val field: String,
    val value: String,
    val period: Long,
    val remaining: Long,
    val issuer: String? = null,
    val account: String? = null,
)

@Serializable
enum class VaultState {
    @SerialName("absent")
    Absent,

    @SerialName("sealed")
    Sealed,

    @SerialName("unsealed")
    Unsealed,
}

@Serializable
data class Device(
    val name: String,
    val local: Boolean,
    val reader: Boolean,
)

@Serializable
data class Invitation(
    val ticket: String,
    val modules: List<List<Boolean>>,
    val expires: Long,
)

@Serializable
data class Review(
    val request: String,
    val code: String,
    val devices: List<Device>,
    val verified: Boolean,
    val waiting: Boolean,
    val approvedHere: Boolean,
)

@Serializable
enum class ErrorCode {
    @SerialName("not-started")
    NotStarted,

    @SerialName("absent")
    Absent,

    @SerialName("exists")
    Exists,

    @SerialName("sealed")
    Sealed,

    @SerialName("password-required")
    PasswordRequired,

    @SerialName("password-rejected")
    PasswordRejected,

    @SerialName("weak-password")
    WeakPassword,

    @SerialName("cancelled")
    Cancelled,

    @SerialName("denied")
    Denied,

    @SerialName("ui-unavailable")
    UiUnavailable,

    @SerialName("session-locked")
    SessionLocked,

    @SerialName("credential-invalidated")
    CredentialInvalidated,

    @SerialName("hardware-unavailable")
    HardwareUnavailable,

    @SerialName("policy-unsupported")
    PolicyUnsupported,

    @SerialName("not-found")
    NotFound,

    @SerialName("changed")
    Changed,

    @SerialName("conflict")
    Conflict,

    @SerialName("invalid")
    Invalid,

    @SerialName("nothing-to-restore")
    NothingToRestore,

    @SerialName("sync")
    Sync,

    @SerialName("failed")
    Failed,
}

@Serializable
enum class Format {
    @SerialName("factorseal")
    FactorSeal,

    @SerialName("cxf-age")
    CxfAge,

    @SerialName("bitwarden-json")
    BitwardenJson,

    @SerialName("1password-csv")
    OnePasswordCsv,

    @SerialName("1password-1pux")
    OnePasswordPux,

    @SerialName("keepass-csv")
    KeePassCsv,
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class TransferKey(
    @EncodeDefault(EncodeDefault.Mode.NEVER) val passphrase: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val keyFile: String? = null,
)

@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class Site(
    @EncodeDefault(EncodeDefault.Mode.NEVER) val web: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val app: String? = null,
)

@Serializable
data class Login(
    val id: String,
    val title: String,
    val username: String,
)

@Serializable
enum class LoginChange {
    @SerialName("added")
    Added,

    @SerialName("updated")
    Updated,

    @SerialName("unchanged")
    Unchanged,
}

@Serializable
sealed interface Request {
    @Serializable
    @SerialName("start")
    data class Start(
        val directory: String,
        val platform: Platform,
    ) : Request

    @Serializable
    @SerialName("status")
    data object Status : Request

    @Serializable
    @SerialName("touch")
    data object Touch : Request

    @Serializable
    @SerialName("create")
    data class Create(
        val groups: List<List<Factor>>,
        val password: String?,
        val lease: Lease,
    ) : Request

    @Serializable
    @SerialName("unlock")
    data class Unlock(
        val group: List<Factor>,
        val password: String?,
        val lease: Lease,
    ) : Request

    @Serializable
    @SerialName("seal")
    data object Seal : Request

    @Serializable
    @SerialName("rate-password")
    data class RatePassword(
        val password: String,
    ) : Request

    @Serializable
    @SerialName("items")
    data object Items : Request

    @Serializable
    @SerialName("item")
    data class OpenItem(
        val id: String,
    ) : Request

    @Serializable
    @SerialName("reveal")
    data class Reveal(
        val id: String,
        val section: String,
        val field: String,
    ) : Request

    @Serializable
    @SerialName("codes")
    data class Codes(
        val id: String,
    ) : Request

    @Serializable
    @SerialName("template")
    data class Template(
        val kind: Kind,
    ) : Request

    @Serializable
    @SerialName("edit")
    data class Edit(
        val id: String,
    ) : Request

    @Serializable
    @SerialName("save")
    data class Save(
        val item: Draft,
        val version: String?,
    ) : Request

    @Serializable
    @SerialName("favorite")
    data class Favorite(
        val id: String,
        val favorite: Boolean,
    ) : Request

    @Serializable
    @SerialName("delete")
    data class Delete(
        val id: String,
        val version: String,
    ) : Request

    @Serializable
    @SerialName("restore")
    data object Restore : Request

    @Serializable
    @SerialName("generate")
    data class Generate(
        val options: GeneratorOptions,
    ) : Request

    @Serializable
    @SerialName("setup-key")
    data class SetupKey(
        val value: String,
        val sameAs: String? = null,
    ) : Request

    @Serializable
    @SerialName("sync-start")
    data class SyncStart(
        val name: String,
    ) : Request

    @Serializable
    @SerialName("sync-stop")
    data object SyncStop : Request

    @Serializable
    @SerialName("sync-view")
    data object SyncView : Request

    @Serializable
    @SerialName("sync-invite")
    data class SyncInvite(
        val name: String,
    ) : Request

    @Serializable
    @SerialName("sync-join")
    data class SyncJoin(
        val ticket: String,
        val name: String,
    ) : Request

    @Serializable
    @SerialName("sync-approve")
    data class SyncApprove(
        val request: String,
    ) : Request

    @Serializable
    @SerialName("sync-cancel")
    data object SyncCancel : Request

    @Serializable
    @SerialName("sync-refresh")
    data object SyncRefresh : Request

    @Serializable
    @SerialName("classify")
    data class Classify(
        val text: String,
    ) : Request

    @Serializable
    @SerialName("export")
    data class Export(
        val format: Format,
        val key: TransferKey?,
    ) : Request

    @Serializable
    @SerialName("import")
    data class Import(
        val format: Format,
        val file: String,
        val key: TransferKey?,
    ) : Request

    @Serializable
    @SerialName("import-commit")
    data class ImportCommit(
        val replace: Boolean,
    ) : Request

    @Serializable
    @SerialName("import-cancel")
    data object ImportCancel : Request

    @Serializable
    @SerialName("logins")
    data class Logins(
        val site: Site,
    ) : Request

    @Serializable
    @SerialName("fill")
    data class Fill(
        val id: String,
        val site: Site,
    ) : Request

    @Serializable
    @SerialName("save-login")
    data class SaveLogin(
        val site: Site,
        val title: String,
        val username: String,
        val password: String,
    ) : Request
}

@Serializable
sealed interface Response {
    @Serializable
    @SerialName("status")
    data class Status(
        val vault: VaultState,
        val groups: List<List<Factor>>,
        val backend: String?,
        val paired: Boolean,
        val idleDeadline: Long?,
        val absoluteDeadline: Long?,
    ) : Response

    @Serializable
    @SerialName("rating")
    data class Rating(
        val score: Int,
        val strength: Strength,
        val acceptable: Boolean,
    ) : Response

    @Serializable
    @SerialName("items")
    data class Items(
        val items: List<Summary>,
    ) : Response

    @Serializable
    @SerialName("item")
    data class Shown(
        val item: Item,
    ) : Response

    @Serializable
    @SerialName("value")
    data class Value(
        val value: String,
    ) : Response

    @Serializable
    @SerialName("codes")
    data class Codes(
        val codes: List<Code>,
    ) : Response

    @Serializable
    @SerialName("draft")
    data class Drafted(
        val item: Item,
    ) : Response

    @Serializable
    @SerialName("saved")
    data class Saved(
        val id: String,
        val version: String,
    ) : Response

    @Serializable
    @SerialName("deleted")
    data object Deleted : Response

    @Serializable
    @SerialName("generated")
    data class Generated(
        val password: String,
        val strength: Strength,
    ) : Response

    @Serializable
    @SerialName("setup-key")
    data class SetupKey(
        val value: String?,
        val issuer: String?,
        val account: String?,
        val same: Boolean = false,
    ) : Response

    @Serializable
    @SerialName("sync")
    data class Sync(
        val running: Boolean = false,
        val paired: Boolean = false,
        val devices: List<Device> = emptyList(),
        val reachable: Int = 0,
        val lastExchange: Long? = null,
        val pending: Int = 0,
        val conflicts: Int = 0,
        val readers: Int = 0,
        val invitation: Invitation? = null,
        val review: Review? = null,
        val joining: Boolean = false,
        val error: String? = null,
    ) : Response

    @Serializable
    @SerialName("scanned")
    data class Scanned(
        val scan: Scan,
    ) : Response

    @Serializable
    @SerialName("file")
    data class File(
        val name: String,
        val data: String,
    ) : Response

    @Serializable
    @SerialName("import-review")
    data class ImportReview(
        val items: Int,
        val preserved: Int,
    ) : Response

    @Serializable
    @SerialName("imported")
    data class Imported(
        val added: Int,
        val replaced: Int,
        val kept: Int,
        val preserved: Int,
    ) : Response

    @Serializable
    @SerialName("logins")
    data class Logins(
        val linked: List<Login>,
        val others: List<Login>,
    ) : Response

    @Serializable
    @SerialName("credentials")
    data class Credentials(
        val username: String,
        val password: String,
    ) : Response

    @Serializable
    @SerialName("login-saved")
    data class LoginSaved(
        val id: String,
        val change: LoginChange,
    ) : Response

    @Serializable
    @SerialName("error")
    data class Error(
        val code: ErrorCode,
        val message: String,
    ) : Response
}

@Serializable
sealed interface Scan {
    @Serializable
    @SerialName("nothing")
    data object Nothing : Scan

    @Serializable
    @SerialName("pairing")
    data class Pairing(
        val ticket: String,
    ) : Scan

    @Serializable
    @SerialName("one-time-password")
    data class OneTimePassword(
        val value: String,
        val issuer: String? = null,
        val account: String? = null,
    ) : Scan

    @Serializable
    @SerialName("unsupported")
    data object Unsupported : Scan
}
