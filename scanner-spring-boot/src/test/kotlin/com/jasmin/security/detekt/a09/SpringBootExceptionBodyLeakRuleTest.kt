package com.jasmin.security.detekt.a09

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringBootExceptionBodyLeakRuleTest {

    private val rule = SpringBootExceptionBodyLeakRule(Config.empty)

    @Test
    fun `flags ExceptionHandler returning ex_message`() {
        val code = """
            @ExceptionHandler(Exception::class)
            fun handleError(ex: Exception): ResponseEntity<String> {
                return ResponseEntity.status(500).body(ex.message)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags ExceptionHandler returning exception stackTrace`() {
        val code = """
            @ExceptionHandler(RuntimeException::class)
            fun handleRuntime(e: RuntimeException): ResponseEntity<String> {
                return ResponseEntity.badRequest().body(e.stackTraceToString())
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores ExceptionHandler returning generic error`() {
        val code = """
            @ExceptionHandler(Exception::class)
            fun handleError(ex: Exception): ResponseEntity<Map<String, String>> {
                return ResponseEntity.status(500).body(mapOf("error" to "Internal server error"))
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores non-ExceptionHandler method with exception message`() {
        val code = """
            fun logError(ex: Exception) {
                logger.error("Error: ${'$'}{ex.message}")
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with ShowSqlEnabled fixture`() {
        val code = """
            spring.jpa.show-sql=true
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
