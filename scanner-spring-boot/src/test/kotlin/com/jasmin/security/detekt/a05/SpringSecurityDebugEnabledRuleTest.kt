package com.jasmin.security.detekt.a05

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringSecurityDebugEnabledRuleTest {

    private val rule = SpringSecurityDebugEnabledRule(Config.empty)

    @Test
    fun `flags EnableWebSecurity with debug true`() {
        val code = """
            @EnableWebSecurity(debug = true)
            class SecurityConfig {
                fun configure() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores EnableWebSecurity without debug`() {
        val code = """
            @EnableWebSecurity
            class SecurityConfig {
                fun configure() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores EnableWebSecurity with debug false`() {
        val code = """
            @EnableWebSecurity(debug = false)
            class SecurityConfig {
                fun configure() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with spring csrf disabled code`() {
        val code = """
            @Configuration
            class SecurityConfig {
                fun configure(http: HttpSecurity) {
                    http.csrf().disable()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
