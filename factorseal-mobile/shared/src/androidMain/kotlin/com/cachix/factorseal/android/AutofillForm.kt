package com.cachix.factorseal.android

import android.app.assist.AssistStructure
import android.content.Context
import android.content.pm.PackageManager
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import com.cachix.factorseal.core.Site

class FormNode<T>(
    val id: T?,
    val text: Boolean,
    val visible: Boolean = true,
    val hints: List<String> = emptyList(),
    val inputType: Int = 0,
    val html: Map<String, String> = emptyMap(),
    val words: List<String> = emptyList(),
    val value: String? = null,
    val domain: String? = null,
    val scheme: String? = null,
    val children: List<FormNode<T>> = emptyList(),
)

class Form<T>(
    val usernames: List<T>,
    val passwords: List<T>,
    val domain: String?,
    val scheme: String?,
    val username: String?,
    val password: String?,
) {
    val ids: List<T> get() = usernames + passwords

    fun site(
        application: String,
        own: String,
        browser: (String) -> Boolean,
    ): Site? = when {
        ids.isEmpty() || application == own -> null
        browser(application) -> domain?.takeIf { scheme.equals("https", ignoreCase = true) }?.let { Site(web = "https://$it") }
        else -> Site(app = application)
    }
}

private enum class Role { Username, Password, Unknown, Other }

private class Candidate<T>(
    val id: T,
    val role: Role,
    val value: String?,
    val domain: String?,
    val scheme: String?,
)

fun <T> form(roots: List<FormNode<T>>): Form<T> {
    val fields = roots.flatMap { candidates(it, null, null) }
    val primary = fields.firstOrNull { it.role == Role.Password } ?: fields.firstOrNull { it.role == Role.Username }
    val scoped = fields.filter { it.domain == primary?.domain }
    val passwords = scoped.filter { it.role == Role.Password }
    val usernames =
        scoped.filter { it.role == Role.Username }.ifEmpty {
            listOfNotNull(scoped.takeWhile { it.role != Role.Password }.lastOrNull()?.takeIf { it.role == Role.Unknown && passwords.isNotEmpty() })
        }
    return Form(
        usernames = usernames.map { it.id },
        passwords = passwords.map { it.id },
        domain = primary?.domain,
        scheme = primary?.scheme,
        username = usernames.firstNotNullOfOrNull { field -> field.value?.takeIf { it.isNotEmpty() } },
        password = passwords.firstNotNullOfOrNull { field -> field.value?.takeIf { it.isNotEmpty() } },
    )
}

fun <T> merged(forms: List<Form<T>>): Form<T>? {
    val last = forms.lastOrNull() ?: return null
    return Form(
        usernames = last.usernames,
        passwords = last.passwords,
        domain = last.domain,
        scheme = last.scheme,
        username = forms.filter { it.domain == last.domain }.lastNotNullOfOrNull { it.username },
        password = last.password,
    )
}

private fun <T, R> List<T>.lastNotNullOfOrNull(transform: (T) -> R?): R? = asReversed().firstNotNullOfOrNull(transform)

private fun <T> candidates(
    node: FormNode<T>,
    domain: String?,
    scheme: String?,
): List<Candidate<T>> {
    if (!node.visible) return emptyList()
    val here = node.domain ?: domain
    val via = if (node.domain != null) node.scheme else scheme
    val own = node.id?.takeIf { node.text && !excluded(node) }?.let { Candidate<T>(it, role(node), node.value, here, via) }
    return listOfNotNull(own) + node.children.flatMap { candidates(it, here, via) }
}

private fun tokens(node: FormNode<*>): List<String> = (node.hints + node.html["autocomplete"].orEmpty().split(' '))
    .map { it.trim().lowercase() }
    .filter { it.isNotEmpty() && it != "on" && it != "off" }

private fun words(node: FormNode<*>): String = (node.words + listOfNotNull(node.html["name"], node.html["id"])).joinToString(" ").lowercase()

private fun excluded(node: FormNode<*>): Boolean = node.html["type"]?.lowercase() in IGNORED_TYPES ||
    (tokens(node) + words(node)).any { text -> IGNORED_WORDS.any { it in text } }

private fun role(node: FormNode<*>): Role {
    val tokens = tokens(node)
    val type = node.html["type"]?.lowercase()
    val words = words(node)
    return when {
        tokens.any { it in PASSWORD_HINTS } -> Role.Password
        tokens.any { it in USERNAME_HINTS } -> Role.Username
        tokens.any { !it.startsWith("section-") && it !in SCOPES } -> Role.Other
        masked(node.inputType) || type == "password" -> Role.Password
        email(node.inputType) || type == "email" -> Role.Username
        PASSWORD_WORDS.any { it in words } -> Role.Password
        USERNAME_WORDS.any { it in words } -> Role.Username
        else -> Role.Unknown
    }
}

private fun masked(inputType: Int): Boolean {
    val variation = inputType and InputType.TYPE_MASK_VARIATION
    return when (inputType and InputType.TYPE_MASK_CLASS) {
        InputType.TYPE_CLASS_TEXT ->
            variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD

        InputType.TYPE_CLASS_NUMBER -> variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD

        else -> false
    }
}

private fun email(inputType: Int): Boolean {
    val variation = inputType and InputType.TYPE_MASK_VARIATION
    return inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_TEXT &&
        (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)
}

private val PASSWORD_HINTS = setOf("password", "current-password", "new-password", "newpassword")
private val USERNAME_HINTS = setOf("username", "newusername", "emailaddress", "email")
private val SCOPES = setOf("shipping", "billing", "home", "work", "mobile", "fax", "pager", "webauthn")
private val PASSWORD_WORDS = listOf("password", "passwd", "pwd")
private val USERNAME_WORDS = listOf("user", "mail", "login", "identifier")
private val IGNORED_WORDS = listOf("search", "one-time-code", "otp", "captcha", "smsotp")
private val IGNORED_TYPES = setOf("hidden", "submit", "button", "checkbox", "radio", "search", "file", "image", "reset")

val BROWSERS =
    mapOf(
        "app.vanadium.browser" to
            setOf(
                "C6:AD:B8:B8:3C:6D:4C:17:D2:92:AF:DE:56:FD:48:8A:51:D3:16:FF:8F:2C:11:C5:41:02:23:BF:F8:A7:DB:B3",
            ),
        "com.android.chrome" to
            setOf(
                "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83",
            ),
        "com.brave.browser" to
            setOf(
                "9C:2D:B7:05:13:51:5F:DB:FB:BC:58:5B:3E:DF:3D:71:23:D4:DC:67:C9:4F:FD:30:63:61:C1:D7:9B:BF:18:AC",
            ),
        "com.brave.browser_beta" to
            setOf(
                "9C:2D:B7:05:13:51:5F:DB:FB:BC:58:5B:3E:DF:3D:71:23:D4:DC:67:C9:4F:FD:30:63:61:C1:D7:9B:BF:18:AC",
            ),
        "com.brave.browser_nightly" to
            setOf(
                "9C:2D:B7:05:13:51:5F:DB:FB:BC:58:5B:3E:DF:3D:71:23:D4:DC:67:C9:4F:FD:30:63:61:C1:D7:9B:BF:18:AC",
            ),
        "com.chrome.beta" to
            setOf(
                "DA:63:3D:34:B6:9E:63:AE:21:03:B4:9D:53:CE:05:2F:C5:F7:F3:C5:3A:AB:94:FD:C2:A2:08:BD:FD:14:24:9C",
                "3D:7A:12:23:01:9A:A3:9D:9E:A0:E3:43:6A:B7:C0:89:6B:FB:4F:B6:79:F4:DE:5F:E7:C2:3F:32:6C:8F:99:4A",
            ),
        "com.chrome.canary" to
            setOf(
                "20:19:DF:A1:FB:23:EF:BF:70:C5:BC:D1:44:3C:5B:EA:B0:4F:3F:2F:F4:36:6E:9A:C1:E3:45:76:39:A2:4C:FC",
            ),
        "com.chrome.dev" to
            setOf(
                "90:44:EE:5F:EE:4B:BC:5E:21:DD:44:66:54:31:C4:EB:1F:1F:71:A3:27:16:A0:BC:92:7B:CB:B3:92:33:CA:BF",
                "3D:7A:12:23:01:9A:A3:9D:9E:A0:E3:43:6A:B7:C0:89:6B:FB:4F:B6:79:F4:DE:5F:E7:C2:3F:32:6C:8F:99:4A",
            ),
        "com.duckduckgo.mobile.android" to
            setOf(
                "BB:7B:B3:1C:57:3C:46:A1:DA:7F:C5:C5:28:A6:AC:F4:32:10:84:56:FE:EC:50:81:0C:7F:33:69:4E:B3:D2:D4",
            ),
        "com.microsoft.emmx" to
            setOf(
                "01:E1:99:97:10:A8:2C:27:49:B4:D5:0C:44:5D:C8:5D:67:0B:61:36:08:9D:0A:76:6A:73:82:7C:82:A1:EA:C9",
            ),
        "com.opera.browser" to
            setOf(
                "5D:6A:FB:F8:7F:65:2A:F0:46:47:AD:A0:DF:63:4C:F2:23:70:90:0B:16:4B:09:D5:0B:D2:3A:A2:CB:52:85:B8",
            ),
        "com.sec.android.app.sbrowser" to
            setOf(
                "34:DF:0E:7A:9F:1C:F1:89:2E:45:C0:56:B4:97:3C:D8:1C:CF:14:8A:40:50:D1:1A:EA:4A:C5:A6:5F:90:0A:42",
            ),
        "com.sec.android.app.sbrowser.beta" to
            setOf(
                "34:DF:0E:7A:9F:1C:F1:89:2E:45:C0:56:B4:97:3C:D8:1C:CF:14:8A:40:50:D1:1A:EA:4A:C5:A6:5F:90:0A:42",
            ),
        "com.vivaldi.browser" to
            setOf(
                "E8:A7:85:44:65:5B:A8:C0:98:17:F7:32:76:8F:56:89:B1:66:2E:C4:B2:BC:5A:0B:C0:EC:13:8D:33:CA:3D:1E",
            ),
        "org.chromium.chrome" to
            setOf(
                "C6:AD:B8:B8:3C:6D:4C:17:D2:92:AF:DE:56:FD:48:8A:51:D3:16:FF:8F:2C:11:C5:41:02:23:BF:F8:A7:DB:B3",
            ),
        "org.mozilla.fenix" to
            setOf(
                "50:04:77:90:88:E7:F9:88:D5:BC:5C:C5:F8:79:8F:EB:F4:F8:CD:08:4A:1B:2A:46:EF:D4:C8:EE:4A:EA:F2:11",
            ),
        "org.mozilla.firefox" to
            setOf(
                "A7:8B:62:A5:16:5B:44:94:B2:FE:AD:9E:76:A2:80:D2:2D:93:7F:EE:62:51:AE:CE:59:94:46:B2:EA:31:9B:04",
            ),
        "org.mozilla.firefox_beta" to
            setOf(
                "A7:8B:62:A5:16:5B:44:94:B2:FE:AD:9E:76:A2:80:D2:2D:93:7F:EE:62:51:AE:CE:59:94:46:B2:EA:31:9B:04",
            ),
        "org.mozilla.focus" to
            setOf(
                "62:03:A4:73:BE:36:D6:4E:E3:7F:87:FA:50:0E:DB:C7:9E:AB:93:06:10:AB:9B:9F:A4:CA:7D:5C:1F:1B:4F:FC",
            ),
        "org.mozilla.klar" to
            setOf(
                "62:03:A4:73:BE:36:D6:4E:E3:7F:87:FA:50:0E:DB:C7:9E:AB:93:06:10:AB:9B:9F:A4:CA:7D:5C:1F:1B:4F:FC",
            ),
    )

private val FINGERPRINT = HexFormat { bytes.byteSeparator = ":" }

fun Context.browser(application: String): Boolean = BROWSERS[application].orEmpty().any { fingerprint ->
    packageManager.hasSigningCertificate(application, fingerprint.hexToByteArray(FINGERPRINT), PackageManager.CERT_INPUT_SHA256)
}

fun AssistStructure.form(): Form<AutofillId> = form((0 until windowNodeCount).map { node(getWindowNodeAt(it).rootViewNode) })

private fun node(view: AssistStructure.ViewNode): FormNode<AutofillId> = FormNode(
    id = view.autofillId,
    text = view.autofillType == View.AUTOFILL_TYPE_TEXT,
    visible = view.visibility == View.VISIBLE,
    hints = view.autofillHints?.toList().orEmpty(),
    inputType = view.inputType,
    html =
    view.htmlInfo
        ?.takeIf { it.tag.equals("input", ignoreCase = true) }
        ?.attributes
        ?.associate { it.first.lowercase() to it.second }
        .orEmpty(),
    words = listOfNotNull(view.idEntry, view.hint),
    value = view.autofillValue?.takeIf { it.isText }?.textValue?.toString(),
    domain = view.webDomain,
    scheme = view.webScheme,
    children = (0 until view.childCount).map { node(view.getChildAt(it)) },
)
