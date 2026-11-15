package com.jasmin.security.detekt.a01

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorInsecureRedirectRuleTest {

    private val rule = KtorInsecureRedirectRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags respondRedirect with variable`() {
        val code = """
            fun configure() {
                get("/redirect") {
                    val target = call.parameters["url"] ?: "/"
                    call.respondRedirect(target)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags respondRedirect with interpolated string`() {
        val code = """
            fun configure() {
                get("/go") {
                    val host = call.parameters["host"]
                    call.respondRedirect("https://${'$'}{host}/")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores respondRedirect with literal path`() {
        val code = """
            fun configure() {
                get("/old") {
                    call.respondRedirect("/new-path")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores respondRedirect with literal full URL`() {
        val code = """
            fun configure() {
                get("/login") {
                    call.respondRedirect("https://auth.example.com/login")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on KtorMissingAuth fixture`() {
        val code = """
            fun configure() {
                routing {
                    get("/health") { call.respond("UP") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
