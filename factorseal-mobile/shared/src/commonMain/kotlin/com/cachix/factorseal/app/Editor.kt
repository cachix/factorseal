package com.cachix.factorseal.app

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.cachix.factorseal.core.Draft
import com.cachix.factorseal.core.Field
import com.cachix.factorseal.core.FieldType
import com.cachix.factorseal.core.Item
import com.cachix.factorseal.core.Kind
import com.cachix.factorseal.core.Section
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.enter_one_value
import com.cachix.factorseal.resources.give_item_a_name
import com.cachix.factorseal.resources.invalid_json
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

const val NOTES_ID = "notes"
const val USERNAME_ID = "username"
const val CUSTOM_SECTION = "custom"

private val pretty = Json { prettyPrint = true }

fun JsonElement?.text(): String = when {
    this == null || this is JsonNull -> ""
    this is JsonPrimitive && isString -> content
    this is JsonPrimitive -> content
    else -> pretty.encodeToString(JsonElement.serializer(), this)
}

private fun JsonElement?.structured(): Boolean = this != null && this !is JsonNull && this !is JsonPrimitive

class Labels(
    val customFields: String,
    val customField: String,
    val website: String,
    val oneTimePassword: String,
    val notes: String,
)

class EditorRow(
    val key: Int,
    val id: String,
    label: String,
    type: FieldType,
    val custom: Boolean,
    value: String,
    val structured: Boolean,
    val stored: Boolean,
    concealed: Boolean,
) {
    val label = TextFieldState(label)
    val value = TextFieldState(value)
    var type by mutableStateOf(type)
    var removed by mutableStateOf(false)
    var hidden by mutableStateOf(false)
    var revealed by mutableStateOf(false)
    var focusing by mutableStateOf(false)
    var problem by mutableStateOf<Message?>(null)
    var notice by mutableStateOf<Message?>(null)
    var replacing by mutableStateOf(false)
    private val flagged = concealed
    private val originalLabel = label
    private val originalValue = value
    private val originalType = type

    val concealed: Boolean get() = flagged || type in ConcealedTypes

    val multiline: Boolean get() = structured || type in MultilineTypes || id == NOTES_ID

    val empty: Boolean get() = value.text.isEmpty()

    val changed: Boolean
        get() = removed || value.text.toString() != originalValue || label.text.toString() != originalLabel || type != originalType

    val original: String get() = originalValue

    fun field(labels: Labels): Field? {
        if (removed) return null
        val text = value.text.toString()
        val element: JsonElement =
            if (structured) {
                runCatching { Json.parseToJsonElement(text) }.getOrElse { JsonPrimitive(text) }
            } else {
                JsonPrimitive(text)
            }
        return Field(
            id = id,
            label =
            label.text
                .toString()
                .trim()
                .ifEmpty { if (custom) labels.customField else "" },
            type = type,
            concealed = concealed,
            filled = text.isNotEmpty(),
            value = element,
        )
    }
}

class EditorSection(
    val id: String,
    val label: String,
    val stored: Boolean,
    rows: List<EditorRow>,
) {
    val rows = mutableStateListOf<EditorRow>().apply { addAll(rows) }

    val visible: List<EditorRow> get() = rows.filter { !it.hidden }
}

sealed interface Addable {
    data class Hidden(
        val row: EditorRow,
    ) : Addable

    data class Template(
        val section: Section,
        val field: Field,
    ) : Addable

    data object Website : Addable

    data class Custom(
        val type: FieldType,
    ) : Addable
}

class Editor private constructor(
    val id: String,
    kind: Kind,
    title: String,
    val favorite: Boolean,
    val notes: String?,
    val version: String?,
    sections: List<EditorSection>,
    private var nextKey: Int,
) {
    var kind by mutableStateOf(kind)
        private set
    val title = TextFieldState(title)
    private val originalTitle = title
    private val originalKind = kind
    var titleProblem by mutableStateOf<Message?>(null)
    var problem by mutableStateOf<Message?>(null)
    var template by mutableStateOf<Item?>(null)
    var original: Item? = null
    val sections = mutableStateListOf<EditorSection>().apply { addAll(sections) }

    val isNew: Boolean get() = version == null

    val rows: List<EditorRow> get() = sections.flatMap { it.rows }

    val dirty: Boolean
        get() =
            if (isNew) {
                title.text.isNotEmpty() || rows.any { !it.empty }
            } else {
                title.text.toString() != originalTitle || kind != originalKind || rows.any { it.changed }
            }

    fun draft(labels: Labels): Draft = Draft(
        id = id,
        kind = kind,
        title = title.text.toString().trim(),
        favorite = favorite,
        notes = notes,
        sections =
        sections.mapNotNull { section ->
            val fields = section.rows.mapNotNull { it.field(labels) }
            if (fields.isEmpty() && !section.stored) null else Section(section.id, section.label, fields)
        },
    )

    fun validate(): Boolean {
        titleProblem = null
        problem = null
        rows.forEach { it.problem = null }
        var valid = true
        rows.filter { it.structured && !it.removed }.forEach { row ->
            if (runCatching { Json.parseToJsonElement(row.value.text.toString()) }.isFailure) {
                row.problem = message(Res.string.invalid_json)
                valid = false
            }
        }
        if (title.text.isBlank()) {
            titleProblem = message(Res.string.give_item_a_name)
            valid = false
        }
        if (isNew && rows.all { it.removed || it.empty }) {
            problem = message(Res.string.enter_one_value)
            valid = false
        }
        return valid
    }

    fun addable(): List<Addable> {
        val present = rows.map { it.id }.toSet()
        val (notes, hidden) = rows.filter { it.hidden && !it.removed }.map { Addable.Hidden(it) }.partition { it.row.id == NOTES_ID }
        val missing =
            template
                ?.sections
                ?.flatMap { section -> section.fields.filter { it.id !in present }.map { Addable.Template(section, it) } }
                .orEmpty()
        val website =
            if (kind == Kind.Login &&
                rows.any { !it.removed && !it.hidden && it.type == FieldType.Url && it.id.startsWith("url") }
            ) {
                listOf(Addable.Website)
            } else {
                emptyList()
            }
        return hidden + missing + website + notes + CustomFieldTypes.map { Addable.Custom(it) }
    }

    fun add(
        addable: Addable,
        labels: Labels,
    ): EditorRow = when (addable) {
        is Addable.Hidden -> {
            addable.row.also { it.hidden = false }
        }

        is Addable.Template -> {
            insertTemplate(addable.section, addable.field)
        }

        Addable.Website -> {
            val section = sections.first { section -> section.rows.any { it.type == FieldType.Url && it.id.startsWith("url") } }
            val last = section.rows.indexOfLast { it.type == FieldType.Url && it.id.startsWith("url") }
            val row = row(unused("url"), labels.website, FieldType.Url, custom = false)
            section.rows.add(last + 1, row)
            row
        }

        is Addable.Custom -> {
            custom(addable.type, "", labels)
        }
    }

    fun custom(
        type: FieldType,
        label: String,
        labels: Labels,
    ): EditorRow {
        val section =
            sections.firstOrNull { it.id == CUSTOM_SECTION }
                ?: EditorSection(CUSTOM_SECTION, labels.customFields, stored = false, rows = emptyList()).also { created ->
                    val notes = sections.indexOfFirst { it.id == NOTES_ID }
                    if (notes >= 0) sections.add(notes, created) else sections.add(created)
                }
        val row = row(unused("custom"), label, type, custom = true)
        section.rows.add(row)
        return row
    }

    fun oneTimePassword(labels: Labels): EditorRow = rows.firstOrNull { it.type == FieldType.Totp && !it.removed }?.also { it.hidden = false }
        ?: template
            ?.sections
            ?.firstNotNullOfOrNull { section -> section.fields.firstOrNull { it.type == FieldType.Totp }?.let { section to it } }
            ?.let { (section, field) ->
                rows.firstOrNull { it.id == field.id }?.also { it.removed = false }
                    ?: insertTemplate(section, field)
            }
        ?: custom(FieldType.Totp, labels.oneTimePassword, labels)

    fun remove(row: EditorRow) {
        val section = sections.first { row in it.rows }
        when {
            !row.empty -> row.removed = true
            row.stored -> row.hidden = true
            else -> section.rows.remove(row)
        }
    }

    fun switched(
        kind: Kind,
        template: Item,
        labels: Labels,
    ) {
        if (!isNew) return
        val typed = rows.filter { !it.empty && !it.removed }
        val fresh =
            template.sections.map { section ->
                EditorSection(section.id, section.label, stored = false, rows = section.fields.map { fresh(it) })
            }
        sections.clear()
        sections.addAll(fresh)
        this.kind = kind
        this.template = template
        typed.forEach { row ->
            val target = rows.firstOrNull { it.id == row.id && it.type == row.type }
            if (target != null) {
                target.value.setTextAndPlaceCursorAtEnd(row.value.text.toString())
            } else {
                custom(row.type, row.label.text.toString(), labels).value.setTextAndPlaceCursorAtEnd(row.value.text.toString())
            }
        }
    }

    private fun insertTemplate(
        section: Section,
        field: Field,
    ): EditorRow {
        val row = fresh(field)
        val target =
            sections.firstOrNull { it.id == section.id }
                ?: EditorSection(section.id, section.label, stored = false, rows = emptyList()).also { created ->
                    val order = template?.sections?.map { it.id }.orEmpty()
                    val position = sections.indexOfFirst { existing -> order.indexOf(existing.id) > order.indexOf(section.id) }
                    if (position >= 0) sections.add(position, created) else sections.add(created)
                }
        val order = section.fields.map { it.id }
        val position = target.rows.indexOfFirst { existing -> order.indexOf(existing.id) > order.indexOf(field.id) }
        if (position >= 0) target.rows.add(position, row) else target.rows.add(row)
        return row
    }

    private fun fresh(field: Field): EditorRow = row(
        field.id,
        field.label,
        field.type,
        custom = false,
        concealed =
        field.concealed || field.id == NOTES_ID,
    )

    private fun row(
        id: String,
        label: String,
        type: FieldType,
        custom: Boolean,
        concealed: Boolean = false,
    ) = EditorRow(nextKey++, id, label, type, custom, "", structured = false, stored = false, concealed = concealed)

    private fun unused(prefix: String): String {
        val ids = rows.map { it.id }.toSet()
        return generateSequence(0) { it + 1 }.map { "$prefix-$it" }.first { it !in ids }
    }

    companion object {
        fun of(
            item: Item,
            isNew: Boolean,
        ): Editor {
            var key = 0
            val sections =
                item.sections.map { section ->
                    EditorSection(
                        section.id,
                        section.label,
                        stored = !isNew,
                        rows =
                        section.fields.map { field ->
                            EditorRow(
                                key = key++,
                                id = field.id,
                                label = field.label,
                                type = field.type,
                                custom = section.id == CUSTOM_SECTION || field.id.startsWith("custom-"),
                                value = field.value.text(),
                                structured = field.value.structured(),
                                stored = !isNew,
                                concealed = field.concealed || field.id == NOTES_ID,
                            ).also { row -> row.hidden = !isNew && row.empty }
                        },
                    )
                }
            return Editor(item.id, item.kind, item.title, item.favorite, item.notes, if (isNew) null else item.version, sections, key)
        }
    }
}
