package com.jasmin.security.detekt.a02

import dev.detekt.test.assertj.assertThat
import dev.detekt.test.lint
import org.junit.jupiter.api.Test

class WeakCipherModeRuleTest {

    private val rule = WeakCipherModeRule()

    @Test
    fun `flags AES ECB mode`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags DES algorithm`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("DES/CBC/PKCS5Padding")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags bare DES algorithm`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("DES")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags RC4 algorithm`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("RC4")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags RC2 algorithm`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("RC2/CBC/PKCS5Padding")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags Blowfish algorithm`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("Blowfish")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores AES GCM mode`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores AES CBC mode`() {
        val code = """
            import javax.crypto.Cipher
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores ECB string not in getInstance`() {
        val code = """
            val description = "ECB mode is not allowed"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // Isolation: must not flag path traversal patterns
    @Test
    fun `does not interfere with path traversal code`() {
        val code = """
            fun readFile(path: String) = java.io.File(path)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
