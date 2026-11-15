package com.jasmin.security.detekt.a07

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorHardcodedDatabasePasswordRuleTest {

    private val rule = KtorHardcodedDatabasePasswordRule(Config.empty)

    @Test
    fun `flags Database_connect with hardcoded 4-arg password`() {
        val code = """
            fun configure() {
                Database.connect("jdbc:postgresql://localhost/mydb", "org.postgresql.Driver", "dbuser", "hardcoded-pass")
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags Database_connect with named password argument`() {
        val code = """
            fun configure() {
                Database.connect(url = "jdbc:h2:mem:test", password = "literal-password")
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores Database_connect with environment variable password`() {
        val code = """
            val pass = System.getenv("DB_PASS") ?: error("DB_PASS not set")
            Database.connect("jdbc:postgresql://localhost/mydb", "org.postgresql.Driver", "user", pass)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores unrelated function calls`() {
        val code = """
            transaction {
                Users.selectAll().toList()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
