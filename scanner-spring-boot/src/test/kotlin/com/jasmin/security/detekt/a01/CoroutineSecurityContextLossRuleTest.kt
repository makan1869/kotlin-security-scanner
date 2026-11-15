package com.jasmin.security.detekt.a01

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class CoroutineSecurityContextLossRuleTest {

    private val rule = CoroutineSecurityContextLossRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags PreAuthorize on suspend fun`() {
        val code = """
            @PreAuthorize("hasRole('ADMIN')")
            suspend fun deleteUser(id: Long) { userService.delete(id) }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags PostAuthorize on suspend fun`() {
        val code = """
            @PostAuthorize("returnObject.owner == authentication.name")
            suspend fun getDocument(id: Long): Document = repo.findById(id)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags Secured on suspend fun`() {
        val code = """
            @Secured("ROLE_ADMIN")
            suspend fun adminAction(): String = "done"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores PreAuthorize on regular non-suspend fun`() {
        val code = """
            @PreAuthorize("hasRole('ADMIN')")
            fun deleteUser(id: Long) { userService.delete(id) }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores suspend fun without security annotation`() {
        val code = """
            suspend fun fetchData(id: Long): Data = repository.findById(id)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `flags RolesAllowed on suspend fun — same proxy issue`() {
        val code = """
            @RolesAllowed("ADMIN")
            suspend fun action(): String = "ok"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on MissingAuthorization fixture`() {
        val code = """
            @GetMapping("/users")
            fun getUsers(): List<User> = userService.findAll()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
