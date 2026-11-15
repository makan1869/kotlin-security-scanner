package com.jasmin.security.detekt.a07

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HardcodedJwtTokenRuleTest {

    private val rule = HardcodedJwtTokenRule(Config.empty)

    @Test
    fun `flags a hardcoded signed JWT literal`() {
        val code = """
            val token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysignature123"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores a value loaded from the environment`() {
        val code = """
            val token = System.getenv("JWT")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores an unrelated string`() {
        val code = """
            val note = "the header starts with eyJ when base64 encoded"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
