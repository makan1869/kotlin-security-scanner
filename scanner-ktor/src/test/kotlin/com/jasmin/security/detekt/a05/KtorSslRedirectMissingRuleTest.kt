package com.jasmin.security.detekt.a05

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorSslRedirectMissingRuleTest {

    private val rule = KtorSslRedirectMissingRule(Config.empty)

    @Test
    fun `flags routing in app setup that installs plugins but no HttpsRedirect`() {
        val code = """
            fun Application.module() {
                install(ContentNegotiation) { json() }
                install(CallLogging)
                routing {
                    get("/health") { call.respond("ok") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores file that only declares routes`() {
        val code = """
            fun Application.routes() {
                routing {
                    get("/") {}
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores routing when HttpsRedirect is present`() {
        val code = """
            fun Application.configure() {
                install(HttpsRedirect) { sslPort = 443 }
                routing {
                    get("/health") { call.respond("ok") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
