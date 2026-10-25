package com.cachix.factorseal.app

import androidx.compose.runtime.Composable
import com.cachix.factorseal.core.Factor
import com.cachix.factorseal.core.FieldType
import com.cachix.factorseal.core.Kind
import com.cachix.factorseal.core.Strength
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.backend_android_strongbox
import com.cachix.factorseal.resources.backend_android_trusted
import com.cachix.factorseal.resources.backend_secure_enclave
import com.cachix.factorseal.resources.backend_tpm
import com.cachix.factorseal.resources.backend_windows_tpm
import com.cachix.factorseal.resources.glyph_card
import com.cachix.factorseal.resources.glyph_clock
import com.cachix.factorseal.resources.glyph_key
import com.cachix.factorseal.resources.glyph_lock
import com.cachix.factorseal.resources.glyph_mail
import com.cachix.factorseal.resources.glyph_phone
import com.cachix.factorseal.resources.glyph_tag
import com.cachix.factorseal.resources.hours
import com.cachix.factorseal.resources.icon_asterisk
import com.cachix.factorseal.resources.icon_book_open
import com.cachix.factorseal.resources.icon_building_2
import com.cachix.factorseal.resources.icon_calendar
import com.cachix.factorseal.resources.icon_case_sensitive
import com.cachix.factorseal.resources.icon_circle_check
import com.cachix.factorseal.resources.icon_circle_user
import com.cachix.factorseal.resources.icon_ellipsis
import com.cachix.factorseal.resources.icon_file
import com.cachix.factorseal.resources.icon_folder
import com.cachix.factorseal.resources.icon_globe
import com.cachix.factorseal.resources.icon_map
import com.cachix.factorseal.resources.icon_square_terminal
import com.cachix.factorseal.resources.icon_user
import com.cachix.factorseal.resources.kind_api_credential
import com.cachix.factorseal.resources.kind_bank_account
import com.cachix.factorseal.resources.kind_card
import com.cachix.factorseal.resources.kind_document
import com.cachix.factorseal.resources.kind_identity
import com.cachix.factorseal.resources.kind_login
import com.cachix.factorseal.resources.kind_other
import com.cachix.factorseal.resources.kind_passport
import com.cachix.factorseal.resources.kind_secure_note
import com.cachix.factorseal.resources.kind_ssh_key
import com.cachix.factorseal.resources.method_biometric
import com.cachix.factorseal.resources.method_password
import com.cachix.factorseal.resources.method_password_and_biometric
import com.cachix.factorseal.resources.minutes
import com.cachix.factorseal.resources.month_1
import com.cachix.factorseal.resources.month_10
import com.cachix.factorseal.resources.month_11
import com.cachix.factorseal.resources.month_12
import com.cachix.factorseal.resources.month_2
import com.cachix.factorseal.resources.month_3
import com.cachix.factorseal.resources.month_4
import com.cachix.factorseal.resources.month_5
import com.cachix.factorseal.resources.month_6
import com.cachix.factorseal.resources.month_7
import com.cachix.factorseal.resources.month_8
import com.cachix.factorseal.resources.month_9
import com.cachix.factorseal.resources.strength_good
import com.cachix.factorseal.resources.strength_strong
import com.cachix.factorseal.resources.strength_weak
import com.cachix.factorseal.resources.type_address
import com.cachix.factorseal.resources.type_boolean
import com.cachix.factorseal.resources.type_card_number
import com.cachix.factorseal.resources.type_date
import com.cachix.factorseal.resources.type_email
import com.cachix.factorseal.resources.type_imported
import com.cachix.factorseal.resources.type_month_year
import com.cachix.factorseal.resources.type_multiline
import com.cachix.factorseal.resources.type_one_time_password
import com.cachix.factorseal.resources.type_password
import com.cachix.factorseal.resources.type_phone
import com.cachix.factorseal.resources.type_reference
import com.cachix.factorseal.resources.type_ssh_key
import com.cachix.factorseal.resources.type_text
import com.cachix.factorseal.resources.type_website
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.pluralStringResource
import org.jetbrains.compose.resources.stringResource
import kotlin.time.Instant

val CustomFieldTypes =
    listOf(
        FieldType.Concealed,
        FieldType.Text,
        FieldType.Url,
        FieldType.Email,
        FieldType.Phone,
        FieldType.Date,
        FieldType.MonthYear,
        FieldType.Totp,
        FieldType.Multiline,
    )

val MultilineTypes = setOf(FieldType.Multiline, FieldType.SshKey, FieldType.Address)

val ConcealedTypes = setOf(FieldType.Concealed, FieldType.Totp, FieldType.CardNumber, FieldType.SshKey, FieldType.Unknown)

fun Kind.label(): StringResource = when (this) {
    Kind.Login -> Res.string.kind_login
    Kind.SecureNote -> Res.string.kind_secure_note
    Kind.Card -> Res.string.kind_card
    Kind.Identity -> Res.string.kind_identity
    Kind.SshKey -> Res.string.kind_ssh_key
    Kind.ApiCredential -> Res.string.kind_api_credential
    Kind.Passport -> Res.string.kind_passport
    Kind.BankAccount -> Res.string.kind_bank_account
    Kind.Document -> Res.string.kind_document
    Kind.Generic -> Res.string.kind_other
}

fun Kind.icon(): DrawableResource = when (this) {
    Kind.Login -> Res.drawable.icon_globe
    Kind.SecureNote -> Res.drawable.icon_file
    Kind.Card -> Res.drawable.glyph_card
    Kind.Identity -> Res.drawable.icon_circle_user
    Kind.SshKey -> Res.drawable.icon_square_terminal
    Kind.ApiCredential -> Res.drawable.glyph_key
    Kind.Passport -> Res.drawable.icon_book_open
    Kind.BankAccount -> Res.drawable.icon_building_2
    Kind.Document -> Res.drawable.icon_folder
    Kind.Generic -> Res.drawable.icon_ellipsis
}

fun FieldType.label(): StringResource = when (this) {
    FieldType.Text -> Res.string.type_text
    FieldType.Concealed -> Res.string.type_password
    FieldType.Url -> Res.string.type_website
    FieldType.Email -> Res.string.type_email
    FieldType.Phone -> Res.string.type_phone
    FieldType.Date -> Res.string.type_date
    FieldType.MonthYear -> Res.string.type_month_year
    FieldType.Totp -> Res.string.type_one_time_password
    FieldType.Multiline -> Res.string.type_multiline
    FieldType.Boolean -> Res.string.type_boolean
    FieldType.CardNumber -> Res.string.type_card_number
    FieldType.SshKey -> Res.string.type_ssh_key
    FieldType.Address -> Res.string.type_address
    FieldType.Reference -> Res.string.type_reference
    FieldType.Unknown -> Res.string.type_imported
}

fun fieldIcon(
    id: String,
    type: FieldType,
): DrawableResource = when (id) {
    "username", "cardholderName", "owner", "fullname", "firstName", "lastName", "initial" -> {
        Res.drawable.icon_user
    }

    "password", "passphrase", "credential", "token" -> {
        Res.drawable.glyph_key
    }

    "code", "cvv", "pin", "telephonePin", "accountNo", "iban" -> {
        Res.drawable.glyph_lock
    }

    "type", "brand" -> {
        Res.drawable.glyph_tag
    }

    "expiry", "expMonth", "expYear", "expiry_date", "expires" -> {
        Res.drawable.icon_calendar
    }

    "bank", "bankName", "company", "department" -> {
        Res.drawable.icon_building_2
    }

    "website" -> {
        Res.drawable.icon_globe
    }

    else -> {
        when (type) {
            FieldType.Text -> Res.drawable.icon_case_sensitive
            FieldType.Concealed, FieldType.SshKey -> Res.drawable.glyph_key
            FieldType.Url -> Res.drawable.icon_globe
            FieldType.Email -> Res.drawable.glyph_mail
            FieldType.Phone -> Res.drawable.glyph_phone
            FieldType.Date, FieldType.MonthYear -> Res.drawable.icon_calendar
            FieldType.Totp -> Res.drawable.glyph_clock
            FieldType.Multiline -> Res.drawable.icon_file
            FieldType.Boolean -> Res.drawable.icon_circle_check
            FieldType.CardNumber -> Res.drawable.glyph_card
            FieldType.Address -> Res.drawable.icon_map
            FieldType.Reference, FieldType.Unknown -> Res.drawable.icon_asterisk
        }
    }
}

@Composable
fun backendLabel(backend: String): String = when (backend) {
    "tpm" -> stringResource(Res.string.backend_tpm)
    "windows-tpm" -> stringResource(Res.string.backend_windows_tpm)
    "secure-enclave" -> stringResource(Res.string.backend_secure_enclave)
    "android-strongbox" -> stringResource(Res.string.backend_android_strongbox)
    "android-trusted-environment" -> stringResource(Res.string.backend_android_trusted)
    else -> backend
}

fun groupLabel(group: List<Factor>): StringResource = when {
    Factor.Password in group && Factor.Biometric in group -> Res.string.method_password_and_biometric
    Factor.Biometric in group -> Res.string.method_biometric
    else -> Res.string.method_password
}

fun Strength.label(): StringResource = when (this) {
    Strength.Weak -> Res.string.strength_weak
    Strength.Good -> Res.string.strength_good
    Strength.Strong -> Res.string.strength_strong
}

@Composable
fun durationLabel(seconds: Long): String = if (seconds % 3600 == 0L) {
    val hours = (seconds / 3600).toInt()
    pluralStringResource(Res.plurals.hours, hours, hours)
} else {
    val minutes = (seconds / 60).toInt()
    pluralStringResource(Res.plurals.minutes, minutes, minutes)
}

private val Months =
    listOf(
        Res.string.month_1,
        Res.string.month_2,
        Res.string.month_3,
        Res.string.month_4,
        Res.string.month_5,
        Res.string.month_6,
        Res.string.month_7,
        Res.string.month_8,
        Res.string.month_9,
        Res.string.month_10,
        Res.string.month_11,
        Res.string.month_12,
    )

@Composable
fun dateLabel(epochSeconds: Long): String {
    val date = Instant.fromEpochSeconds(epochSeconds).toLocalDateTime(TimeZone.currentSystemDefault()).date
    return "${date.day} ${stringResource(Months[date.month.ordinal])} ${date.year}"
}

fun grouped(code: String): String {
    val half = (code.length + 1) / 2
    return "${code.take(half)} ${code.drop(half)}"
}
