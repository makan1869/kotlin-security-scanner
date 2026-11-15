package com.jasmin.security.detekt.a05

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorCorsAnyHeaderRuleTest {

    private val rule = KtorCorsAnyHeaderRule(Config.empty)

    @Test
    fun `flags anyHeader in a CORS block`() {
        val code = """
            fun config(cors: Any) {
                cors.apply { anyHeader() }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores explicit allowHeader calls`() {
        val code = """
            fun config(cors: Any) {
                cors.apply { allowHeader("Authorization") }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
