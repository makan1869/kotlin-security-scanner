package com.jasmin.security.detekt.a03

import dev.detekt.test.assertj.assertThat
import dev.detekt.test.lint
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.provider.ValueSource
import org.junit.jupiter.params.ParameterizedTest

class SqlInjectionRuleTest {

    private val rule = SqlInjectionRule()

    @Test
    fun `flags string interpolation in SELECT`() {
        val code = """
            fun find(name: String) = "SELECT * FROM users WHERE name = '${'$'}name'"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags string interpolation in DELETE`() {
        val code = """
            fun delete(id: Int) = "DELETE FROM orders WHERE id = ${'$'}id"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags string interpolation in UPDATE`() {
        val code = """
            fun update(val1: String, id: Int) = "UPDATE items SET name = '${'$'}val1' WHERE id = ${'$'}id"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags string interpolation in INSERT`() {
        val code = """
            fun insert(name: String) = "INSERT INTO users (name) VALUES ('${'$'}name')"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags string concatenation in SELECT`() {
        val code = """
            fun find(userId: String): String {
                return "SELECT * FROM users WHERE id = " + userId
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores parameterized query with colon param`() {
        val code = """
            val query = "SELECT * FROM users WHERE name = :name"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores parameterized query with question mark`() {
        val code = """
            val query = "SELECT * FROM users WHERE id = ?"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores plain string sql without variables`() {
        val code = """
            val query = "SELECT * FROM users WHERE active = true"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // Isolation: must not flag hardcoded credential patterns
    @Test
    fun `does not interfere with hardcoded credential code`() {
        val code = """val dbPassword = "myS3cretPass!"""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Statement shapes, not loose keywords ─────────────────────────────────

    @Test
    fun `flags an interpolated fragment after a statement that starts with SELECT`() {
        val code = """fun count(from: String) = "SELECT count(*) ${'$'}from""""
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags an interpolated value compared in a WHERE clause`() {
        val code = """fun filter(id: String) = "WHERE id = ${'$'}id""""
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags lower-case SQL`() {
        val code = """fun find(name: String) = "select * from users where name = '${'$'}name'""""
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "the head moved from \${'$'}old to \${'$'}new",
            "a reviewer joined \${'$'}team and approved",
            "deleted \${'$'}count rows where they were stale",
            "updatedAt=\${'$'}updatedAt deletedAt=\${'$'}deletedAt",
            "query{pullRequests(orderBy:{field:UPDATED_AT}) \${'$'}fields}",
            "please select one of \${'$'}options",
        ],
    )
    fun `ignores prose and identifiers that only contain SQL words`(text: String) {
        val code = "fun message(old: String, new: String, team: String, count: Int, updatedAt: String, deletedAt: String, fields: String, options: String) = \"$text\""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores a message concatenated after prose that only contains SQL words`() {
        val code = """fun message(team: String) = "approved from the list of " + team"""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
