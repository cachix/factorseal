package com.cachix.factorseal.app

import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import com.cachix.factorseal.core.Field
import com.cachix.factorseal.core.FieldType
import com.cachix.factorseal.core.Item
import com.cachix.factorseal.core.Kind
import com.cachix.factorseal.core.Section
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EditorTest {
    private val labels = Labels("Custom fields", "Custom field", "Website", "One-time password", "Notes")

    private fun field(
        id: String,
        label: String,
        type: FieldType,
        value: String = "",
    ) = Field(id, label, type, concealed = type == FieldType.Concealed || type == FieldType.Totp, filled = value.isNotEmpty(), value = JsonPrimitive(value))

    private fun login(
        username: String = "yurii@example.com",
        version: String? = "1",
    ) = Item(
        id = "github",
        kind = Kind.Login,
        title = if (version == null) "" else "GitHub",
        favorite = false,
        sections =
        listOf(
            Section(
                "login",
                "Login",
                listOf(
                    field("username", "Username", FieldType.Text, username),
                    field("password", "Password", FieldType.Concealed),
                    field("url", "Website", FieldType.Url),
                    field("totp", "One-time password", FieldType.Totp),
                ),
            ),
            Section("notes", "Notes", listOf(field(NOTES_ID, "Notes", FieldType.Multiline))),
        ),
        version = version,
    )

    private fun Editor.row(id: String) = rows.first { it.id == id }

    private fun Editor.offered() = addable().filterNot { it is Addable.Custom }.map {
        when (it) {
            is Addable.Hidden -> it.row.id
            is Addable.Template -> "template:${it.field.id}"
            Addable.Website -> "another website"
            is Addable.Custom -> error("filtered")
        }
    }

    @Test
    fun an_item_is_dirty_only_while_a_value_differs_from_the_saved_one() {
        val editor = Editor.of(login(), isNew = false)
        assertFalse(editor.dirty)
        editor.row("username").value.setTextAndPlaceCursorAtEnd("someone@example.com")
        assertTrue(editor.dirty)
        editor.row("username").value.setTextAndPlaceCursorAtEnd("yurii@example.com")
        assertFalse(editor.dirty)
        editor.title.setTextAndPlaceCursorAtEnd("GitHub work")
        assertTrue(editor.dirty)
    }

    @Test
    fun empty_saved_fields_wait_in_the_add_menu_with_notes_last() {
        val editor = Editor.of(login(), isNew = false)
        assertEquals(listOf("username"), editor.rows.filterNot { it.hidden }.map { it.id })
        assertEquals(listOf("password", "url", "totp", NOTES_ID), editor.offered())
    }

    @Test
    fun another_website_is_offered_only_next_to_a_visible_one() {
        val editor = Editor.of(login(), isNew = false)
        editor.add(editor.addable().first { it is Addable.Hidden && it.row.id == "url" }, labels)
        assertEquals(listOf("password", "totp", "another website", NOTES_ID), editor.offered())
        val added = editor.add(Addable.Website, labels)
        assertEquals("url-0", added.id)
        assertEquals(listOf("username", "url", "url-0"), editor.sections.first().visible.map { it.id })
    }

    @Test
    fun removing_a_filled_field_strikes_it_out_and_leaves_it_out_of_the_saved_item() {
        val editor = Editor.of(login(), isNew = false)
        editor.remove(editor.row("username"))
        assertTrue(editor.row("username").removed)
        assertTrue(editor.dirty)
        val draft = editor.draft(labels)
        assertEquals(listOf("password", "url", "totp"), draft.sections.first().fields.map { it.id })
        assertEquals(listOf("login", "notes"), draft.sections.map { it.id })
    }

    @Test
    fun removing_an_empty_new_field_drops_it_entirely() {
        val editor = Editor.of(login(), isNew = false)
        val custom = editor.custom(FieldType.Text, "", labels)
        editor.remove(custom)
        assertTrue(editor.rows.none { it.key == custom.key })
    }

    @Test
    fun custom_fields_sit_before_notes_and_get_a_default_name() {
        val editor = Editor.of(login(), isNew = false)
        editor.custom(FieldType.Text, "", labels).value.setTextAndPlaceCursorAtEnd("recovery code")
        assertEquals(listOf("login", CUSTOM_SECTION, "notes"), editor.sections.map { it.id })
        val saved = editor.draft(labels).sections.first { it.id == CUSTOM_SECTION }.fields.single()
        assertEquals("Custom field", saved.label)
        assertEquals(JsonPrimitive("recovery code"), saved.value)
    }

    @Test
    fun a_new_item_needs_a_name_and_at_least_one_value() {
        val editor = Editor.of(login(username = "", version = null), isNew = true)
        assertTrue(editor.isNew)
        assertFalse(editor.dirty)
        assertFalse(editor.validate())
        assertNotNull(editor.titleProblem)
        assertNotNull(editor.problem)
        editor.title.setTextAndPlaceCursorAtEnd("GitHub")
        editor.row("username").value.setTextAndPlaceCursorAtEnd("yurii@example.com")
        assertTrue(editor.validate())
        assertNull(editor.titleProblem)
        assertNull(editor.problem)
    }

    @Test
    fun structured_values_must_stay_valid_json() {
        val address = Field("address", "Address", FieldType.Address, concealed = false, filled = true, value = buildJsonObject { put("city", "Kyiv") })
        val item = login().copy(sections = listOf(Section("identity", "Identity", listOf(address))))
        val editor = Editor.of(item, isNew = false)
        val row = editor.row("address")
        assertTrue(row.structured)
        assertTrue(editor.validate())
        row.value.setTextAndPlaceCursorAtEnd("{\"city\": ")
        assertFalse(editor.validate())
        assertNotNull(row.problem)
    }

    @Test
    fun switching_the_kind_of_a_new_item_keeps_what_was_typed() {
        val editor = Editor.of(login(username = "", version = null), isNew = true)
        editor.row("username").value.setTextAndPlaceCursorAtEnd("yurii")
        val note =
            Item(
                id = "github",
                kind = Kind.SecureNote,
                title = "",
                favorite = false,
                sections = listOf(Section("notes", "Notes", listOf(field(NOTES_ID, "Notes", FieldType.Multiline)))),
            )
        editor.switched(Kind.SecureNote, note, labels)
        assertEquals(Kind.SecureNote, editor.kind)
        val kept = editor.rows.single { it.custom }
        assertEquals("Username", kept.label.text.toString())
        assertEquals("yurii", kept.value.text.toString())
    }
}
