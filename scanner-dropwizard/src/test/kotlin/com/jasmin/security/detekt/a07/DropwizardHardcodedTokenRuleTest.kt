package com.jasmin.security.detekt.a07

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardHardcodedTokenRuleTest {

    private val rule = DropwizardHardcodedTokenRule(Config.empty)

    @Test
    fun `flags hardcoded value in apiKey field`() {
        val code = """
            class MyConfig {
                val apiKey = "sk-prod-abc123def456"
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags hardcoded value in token field`() {
        val code = """
            class MyConfig {
                val accessToken = "Bearer eyJhbGciOiJIUzI1NiJ9"
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags hardcoded value in secret field`() {
        val code = """
            class MyConfig {
                val clientSecret = "super-secret-value"
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores non-sensitive field names`() {
        val code = """
            class MyConfig {
                val baseUrl = "https://api.example.com"
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores sensitive field loaded from environment`() {
        val code = """
            class MyConfig {
                val apiKey: String = System.getenv("API_KEY") ?: error("API_KEY not set")
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
