package com.jasmin.security.detekt.a06

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class RegexDenialOfServiceRuleTest {

    private val rule = RegexDenialOfServiceRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags nested plus quantifier (a+)+`() {
        val code = """
            val r = Regex("(a+)+")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags character class with star inside group (word+)*`() {
        val code = """
            val r = Regex("([a-zA-Z]+)*")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags alternation inside repeated group (a or aa)+`() {
        val code = """
            val emailValidator = Regex("(a|aa)+end")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags toRegex with catastrophic pattern`() {
        val code = """
            val r = "(\\w+)+".toRegex()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags grouped quantifier followed by quantifier (word dot)+`() {
        val code = """
            val r = Regex("(\\w+\\.)+\\w+")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores simple character class`() {
        val code = """
            val r = Regex("[a-z]+")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores alphanumeric character class`() {
        val code = """
            val r = Regex("[a-z0-9]+")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores anchored pattern`() {
        val code = """
            val r = Regex("^[0-9]{1,10}${'$'}")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores Regex with variable pattern`() {
        val code = """
            fun compile(pattern: String) = Regex(pattern)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on HardcodedCredentials fixture`() {
        val code = """
            val password = "hardcoded-secret"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
