package com.jasmin.security.detekt.a03

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorXssResponseRuleTest {

    private val rule = KtorXssResponseRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags respondText with Html and dynamic variable content`() {
        val code = """
            fun configure() {
                get("/page") {
                    val content = call.parameters["body"]
                    call.respondText(content, ContentType.Text.Html)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags respondText with Html named arg and interpolated content`() {
        val code = """
            fun configure() {
                get("/view") {
                    val name = call.parameters["name"]
                    call.respondText("<h1>${'$'}{name}</h1>", ContentType.Text.Html)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores respondText with plain text content type`() {
        val code = """
            fun configure() {
                get("/data") {
                    call.respondText("hello world", ContentType.Text.Plain)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores respondText with literal Html content`() {
        val code = """
            fun configure() {
                get("/page") {
                    call.respondText("<h1>Hello World</h1>", ContentType.Text.Html)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on KtorInsecureRedirect fixture`() {
        val code = """
            fun configure() {
                get("/redirect") {
                    val target = call.parameters["url"] ?: "/"
                    call.respondRedirect(target)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
