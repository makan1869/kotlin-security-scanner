package com.jasmin.security.detekt.a01

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorWebSocketNoAuthRuleTest {

    private val rule = KtorWebSocketNoAuthRule(Config.empty)

    @Test
    fun `flags webSocket without authenticate`() {
        val code = """
            fun Application.configureRoutes() {
                routing {
                    webSocket("/chat") {
                        for (frame in incoming) { outgoing.send(frame) }
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores webSocket inside authenticate block`() {
        val code = """
            fun Application.configureRoutes() {
                routing {
                    authenticate("jwt") {
                        webSocket("/chat") {
                            for (frame in incoming) { outgoing.send(frame) }
                        }
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with missing auth routing code`() {
        val code = """
            fun Application.configureRoutes() {
                routing {
                    get("/admin/users") { call.respondText("admin data") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
