package com.jasmin.security.detekt.a07

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecureRememberMeRuleTest {

    private val rule = InsecureRememberMeRule(Config.empty)

    @Test
    fun `flags rememberMe with hardcoded key`() {
        val code = """
            class SecurityConfig {
                fun configure(http: HttpSecurity) {
                    http.rememberMe().key("myStaticRememberMeKey")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores rememberMe with environment variable key`() {
        val code = """
            class SecurityConfig {
                fun configure(http: HttpSecurity) {
                    http.rememberMe().key(System.getenv("REMEMBER_ME_KEY"))
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores key call outside rememberMe chain`() {
        val code = """
            class Config {
                fun setup() {
                    mapOf("key" to "value")
                    someMap.key("lookup")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with hardcoded credentials code`() {
        val code = """
            class Service {
                val password = "secret123"
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
