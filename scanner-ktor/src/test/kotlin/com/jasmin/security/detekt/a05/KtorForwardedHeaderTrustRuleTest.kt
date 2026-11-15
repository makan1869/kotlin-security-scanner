package com.jasmin.security.detekt.a05

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorForwardedHeaderTrustRuleTest {

    private val rule = KtorForwardedHeaderTrustRule(Config.empty)

    @Test
    fun `flags install ForwardedHeaders`() {
        val code = """
            fun Application.configureProxy() {
                install(ForwardedHeaders)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags install XForwardedHeaders`() {
        val code = """
            fun Application.configureProxy() {
                install(XForwardedHeaders)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores install of other plugins`() {
        val code = """
            fun Application.configure() {
                install(ContentNegotiation) {
                    json()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores install ForwardedHeaders with trustProxyHeaders allowlist`() {
        val code = """
            fun Application.configureProxy() {
                install(ForwardedHeaders) {
                    trustProxyHeaders = listOf("10.0.0.1/24")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with session cookie domain missing code`() {
        val code = """
            fun Application.configureSessions() {
                install(Sessions) {
                    cookie<UserSession>("SESSION") {
                        cookie.path = "/"
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
