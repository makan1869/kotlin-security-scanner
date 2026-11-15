package com.jasmin.security.detekt.a07

import dev.detekt.test.assertj.assertThat
import dev.detekt.test.lint
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.provider.ValueSource
import org.junit.jupiter.params.ParameterizedTest

class HardcodedCredentialsRuleTest {

    private val rule = HardcodedCredentialsRule()

    @Test
    fun `flags hardcoded password`() {
        val code = """val password = "supersecret123""""
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags hardcoded api key`() {
        val code = """val apiKey = "sk-prod-abc123xyz""""
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags hardcoded token`() {
        val code = """val authToken = "Bearer eyJhbGciOiJSUzI1NiJ9""""
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags hardcoded client secret`() {
        val code = """val clientSecret = "my-oauth-secret-value""""
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores spring property placeholder`() {
        val code = """val password = "${'$'}{app.db.password}""""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores empty string`() {
        val code = """val password = """""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores short value`() {
        val code = """val pwd = "ab""""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores placeholder value`() {
        val code = """val password = "changeme""""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores non-credential variable names`() {
        val code = """val username = "admin123""""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // Isolation: must not flag SQL injection patterns
    @Test
    fun `does not interfere with sql injection code`() {
        val code = """
            fun findUser(username: String): String {
                return "SELECT * FROM users WHERE username = '${'$'}username'"
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Names: the credential word must be the head noun ─────────────────────

    @ParameterizedTest
    @ValueSource(
        strings = [
            "dbPassword", "DB_PASSWORD", "pwd", "passphrase", "clientSecret", "authToken", "API_KEY", "APIKey",
            "privateKey", "accessKey", "signingKey", "credentials", "apiKeyValue", "authHeader", "secretKeyBase64",
        ],
    )
    fun `flags a credential name`(name: String) {
        val code = "val $name = \"s3cr3t-value-123\""
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "author", "RULE_HUMAN_AUTHOR", "AUTHOR_LOGIN", "TOKEN_LIMIT_FINISH_REASON", "maxTokens", "tokenCount",
            "passwordHash", "secretName", "keyId", "oauthProvider", "tokenizer",
        ],
    )
    fun `ignores a name where the credential word is only a qualifier or part of a longer word`(name: String) {
        val code = "val $name = \"s3cr3t-value-123\""
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
