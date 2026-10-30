package com.cachix.factorseal.android

import android.text.InputType
import com.cachix.factorseal.core.Site
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AutofillFormTest {
    private val password = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    private val email = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
    private val plain = InputType.TYPE_CLASS_TEXT
    private val verified = setOf("com.android.chrome", "org.mozilla.firefox")

    private fun field(
        id: Int,
        inputType: Int = plain,
        hints: List<String> = emptyList(),
        html: Map<String, String> = emptyMap(),
        words: List<String> = emptyList(),
        value: String? = null,
        visible: Boolean = true,
    ) = FormNode(id, text = true, visible = visible, hints = hints, inputType = inputType, html = html, words = words, value = value)

    private fun group(
        vararg children: FormNode<Int>,
        domain: String? = null,
        scheme: String? = null,
        visible: Boolean = true,
    ) = FormNode(null, text = false, visible = visible, domain = domain, scheme = scheme, children = children.toList())

    @Test
    fun app_fields_are_found_by_their_autofill_hints_and_belong_to_the_app() {
        val form = form(listOf(group(field(1, hints = listOf("username")), field(2, hints = listOf("password")), field(3, words = listOf("note")))))
        assertEquals(listOf(1), form.usernames)
        assertEquals(listOf(2), form.passwords)
        assertEquals(Site(app = "com.example.mail"), form.site("com.example.mail", own = "com.cachix.factorseal", verified::contains))
        assertNull(form.site("com.cachix.factorseal", own = "com.cachix.factorseal", verified::contains))
    }

    @Test
    fun fields_without_hints_are_recognised_by_their_type_or_name() {
        val typed = form(listOf(group(field(1, email), field(2, password))))
        assertEquals(listOf(1) to listOf(2), typed.usernames to typed.passwords)
        val named = form(listOf(group(field(1, words = listOf("login_field")), field(2, words = listOf("pwd")))))
        assertEquals(listOf(1) to listOf(2), named.usernames to named.passwords)
        val guessed = form(listOf(group(field(1, words = listOf("first")), field(2, words = listOf("second")), field(3, password))))
        assertEquals(listOf(2) to listOf(3), guessed.usernames to guessed.passwords)
        val explicit = form(listOf(group(field(1, hints = listOf("postalCode"), words = listOf("user_zip")), field(2, password))))
        assertEquals(emptyList<Int>() to listOf(2), explicit.usernames to explicit.passwords)
    }

    @Test
    fun hidden_search_and_one_time_code_fields_are_left_alone() {
        val form =
            form(
                listOf(
                    group(
                        field(1, words = listOf("search_box")),
                        field(2, hints = listOf("one-time-code")),
                        group(field(3, email), field(4, password), visible = false),
                        field(5, password, visible = false),
                    ),
                ),
            )
        assertEquals(emptyList(), form.ids)
        assertNull(form.site("com.example", own = "com.cachix.factorseal", verified::contains))
    }

    @Test
    fun browsers_fill_secure_pages_by_their_domain() {
        val page =
            group(
                field(1, html = mapOf("type" to "search", "name" to "q")),
                field(2, html = mapOf("type" to "text", "name" to "login", "autocomplete" to "section-main username")),
                field(3, html = mapOf("type" to "password", "autocomplete" to "current-password")),
                field(4, html = mapOf("type" to "hidden", "name" to "authenticity_token")),
                domain = "github.com",
                scheme = "https",
            )
        val form = form(listOf(group(page)))
        assertEquals(listOf(2) to listOf(3), form.usernames to form.passwords)
        assertEquals(Site(web = "https://github.com"), form.site("com.android.chrome", own = "com.cachix.factorseal", verified::contains))
        assertEquals(Site(app = "com.example.reader"), form.site("com.example.reader", own = "com.cachix.factorseal", verified::contains))
        val insecure = form(listOf(group(field(1, password), domain = "github.com", scheme = "http")))
        assertNull(insecure.site("org.mozilla.firefox", own = "com.cachix.factorseal", verified::contains))
        assertNull(form(listOf(group(field(1, password)))).site("com.android.chrome", own = "com.cachix.factorseal", verified::contains))
        val unknown = form(listOf(group(field(1, password), domain = "github.com")))
        assertNull(unknown.site("com.android.chrome", own = "com.cachix.factorseal", verified::contains))
    }

    @Test
    fun a_browser_with_an_unknown_signature_is_treated_as_an_app() {
        val form = form(listOf(group(field(1, password), domain = "github.com", scheme = "https")))
        assertEquals(Site(app = "com.android.chrome"), form.site("com.android.chrome", own = "com.cachix.factorseal") { false })
    }

    @Test
    fun a_login_frame_from_another_domain_is_filled_for_that_domain_only() {
        val form =
            form(
                listOf(
                    group(
                        field(1, email),
                        group(field(2, email), field(3, password), domain = "accounts.example.com", scheme = "https"),
                        domain = "shop.example.org",
                        scheme = "https",
                    ),
                ),
            )
        assertEquals(listOf(2) to listOf(3), form.usernames to form.passwords)
        assertEquals("accounts.example.com", form.domain)
    }

    @Test
    fun saving_takes_the_username_from_an_earlier_step_of_the_same_sign_in() {
        val first = form(listOf(group(field(1, email, value = "alice@example.com"), domain = "example.com")))
        val second = form(listOf(group(field(2, password, value = "secret"), domain = "example.com")))
        val elsewhere = form(listOf(group(field(3, email, value = "mallory@example.org"), domain = "example.org")))
        val merged = merged(listOf(first, elsewhere, second))
        assertEquals("alice@example.com" to "secret", merged?.username to merged?.password)
        assertNull(merged(emptyList<Form<Int>>()))
    }
}
