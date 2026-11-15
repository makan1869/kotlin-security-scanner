package com.jasmin.security.detekt.a07

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringBootNoOpPasswordEncoderRuleTest {

    private val rule = SpringBootNoOpPasswordEncoderRule(Config.empty)

    @Test
    fun `flags NoOpPasswordEncoder getInstance`() {
        val code = """
            @Bean
            fun passwordEncoder(): PasswordEncoder = NoOpPasswordEncoder.getInstance()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores BCryptPasswordEncoder`() {
        val code = """
            @Bean
            fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores Argon2PasswordEncoder`() {
        val code = """
            @Bean
            fun passwordEncoder(): PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with InsecurePasswordEncoder fixture`() {
        val code = """
            @Bean
            fun encoder() = MessageDigestPasswordEncoder("MD5")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
