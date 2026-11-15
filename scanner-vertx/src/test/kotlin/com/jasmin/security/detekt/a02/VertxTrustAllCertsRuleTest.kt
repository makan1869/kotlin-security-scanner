package com.jasmin.security.detekt.a02

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxTrustAllCertsRuleTest {

    private val rule = VertxTrustAllCertsRule(Config.empty)

    @Test
    fun `flags setTrustAll true`() {
        val code = """
            fun client() = HttpClientOptions().setSsl(true).setTrustAll(true)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags setVerifyHost false`() {
        val code = """
            fun client() = WebClientOptions().setVerifyHost(false)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores secure settings`() {
        val code = """
            fun client() = WebClientOptions().setTrustAll(false).setVerifyHost(true)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
