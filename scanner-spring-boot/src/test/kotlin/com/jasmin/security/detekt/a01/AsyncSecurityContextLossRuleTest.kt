package com.jasmin.security.detekt.a01

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AsyncSecurityContextLossRuleTest {

    private val rule = AsyncSecurityContextLossRule(Config.empty)

    @Test
    fun `flags async method that reads SecurityContextHolder`() {
        val code = """
            import org.springframework.scheduling.annotation.Async
            class Service {
                @Async
                fun process() {
                    val auth = SecurityContextHolder.getContext().authentication
                    println(auth)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores async method that does not access SecurityContextHolder`() {
        val code = """
            import org.springframework.scheduling.annotation.Async
            class Service {
                @Async
                fun process() {
                    println("hello")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores non-async method that reads SecurityContextHolder`() {
        val code = """
            class Service {
                fun process() {
                    val auth = SecurityContextHolder.getContext().authentication
                    println(auth)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with coroutine security context loss code`() {
        val code = """
            import kotlinx.coroutines.withContext
            class Service {
                suspend fun process() {
                    withContext(Dispatchers.IO) { println("hello") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
