package com.jasmin.security.detekt.a07

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusHardcodedConfigPropertyDefaultRuleTest {

    private val rule = QuarkusHardcodedConfigPropertyDefaultRule(Config.empty)

    @Test
    fun `flags @ConfigProperty with hardcoded secret default`() {
        val code = """
            @ConfigProperty(name = "jwt.secret", defaultValue = "my-hardcoded-secret")
            lateinit var jwtSecret: String
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags @ConfigProperty with hardcoded password default`() {
        val code = """
            @ConfigProperty(name = "db.password", defaultValue = "changeit")
            lateinit var dbPassword: String
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores @ConfigProperty without default`() {
        val code = """
            @ConfigProperty(name = "jwt.secret")
            lateinit var jwtSecret: String
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores @ConfigProperty with non-sensitive default`() {
        val code = """
            @ConfigProperty(name = "server.port", defaultValue = "8080")
            var serverPort: Int = 8080
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with other Quarkus annotations`() {
        val code = """
            @GET
            @Path("/health")
            fun health(): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
