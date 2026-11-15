package com.jasmin.security.detekt.a01

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PredictableTempFileRuleTest {

    private val rule = PredictableTempFileRule(Config.empty)

    @Test
    fun `flags File at a fixed tmp path`() {
        val code = """
            import java.io.File
            fun tmp() = File("/tmp/session-data.txt")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags File under var tmp`() {
        val code = """
            import java.io.File
            fun tmp() = File("/var/tmp/cache.bin")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores File at a non-temp path`() {
        val code = """
            import java.io.File
            fun data() = File("/home/app/data.txt")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores File built from a directory variable`() {
        val code = """
            import java.io.File
            fun data(dir: File) = File(dir, "data.txt")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
