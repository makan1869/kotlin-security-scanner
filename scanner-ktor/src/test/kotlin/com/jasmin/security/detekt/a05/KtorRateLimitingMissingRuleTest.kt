package com.jasmin.security.detekt.a05

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorRateLimitingMissingRuleTest {

    private val rule = KtorRateLimitingMissingRule(Config.empty)

    @Test
    fun `flags post login route without rate limiting`() {
        val code = """
            routing {
                post("/login") {
                    val creds = call.receive<Credentials>()
                    val user = authService.authenticate(creds)
                    call.respond(user)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags post auth route without rate limiting`() {
        val code = """
            routing {
                post("/auth/token") {
                    call.respond(tokenService.generate())
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores login route wrapped in rateLimited`() {
        val code = """
            routing {
                rateLimited {
                    post("/login") {
                        val creds = call.receive<Credentials>()
                        call.respond(authService.authenticate(creds))
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores authors route (substring of auth)`() {
        val code = """
            routing {
                post("/authors") {
                    val author = call.receive<Author>()
                    call.respond(authorService.create(author))
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores non-auth routes`() {
        val code = """
            routing {
                post("/orders") {
                    val order = call.receive<Order>()
                    call.respond(orderService.create(order))
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
