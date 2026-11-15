package com.jasmin.security.detekt.a07

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class GitHubTokenRuleTest {

    private val rule = GitHubTokenRule(Config.empty)

    @Test
    fun `flags a classic personal access token`() {
        val code = """
            val token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags a fine-grained personal access token`() {
        val code = """
            val token = "github_pat_0123456789abcdefghijklmn"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores a value loaded from the environment`() {
        val code = """
            val token = System.getenv("GITHUB_TOKEN")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores an unrelated string`() {
        val code = """
            val repo = "github.com/acme/widgets"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
