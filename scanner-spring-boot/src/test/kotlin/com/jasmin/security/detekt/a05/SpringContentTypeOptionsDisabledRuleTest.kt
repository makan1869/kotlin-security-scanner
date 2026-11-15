package com.jasmin.security.detekt.a05

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringContentTypeOptionsDisabledRuleTest {

    private val rule = SpringContentTypeOptionsDisabledRule(Config.empty)

    @Test
    fun `flags contentTypeOptions disabled in a lambda`() {
        val code = """
            fun config(http: Any) {
                http.headers { contentTypeOptions { disable() } }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags fluent contentTypeOptions disable`() {
        val code = """
            fun config(http: Any) {
                http.headers().contentTypeOptions().disable()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores headers without disabling contentTypeOptions`() {
        val code = """
            fun config(http: Any) {
                http.headers { contentTypeOptions { } }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
