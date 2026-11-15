package com.jasmin.security.detekt.a03

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardSelfValidatingELRuleTest {

    private val rule = DropwizardSelfValidatingELRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags buildConstraintViolationWithTemplate with variable message`() {
        val code = """
            fun isValid(value: String, context: ConstraintValidatorContext): Boolean {
                context.buildConstraintViolationWithTemplate(value).addConstraintViolation()
                return false
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags buildConstraintViolationWithTemplate with interpolated message`() {
        val code = """
            fun isValid(value: String, context: ConstraintValidatorContext): Boolean {
                context.buildConstraintViolationWithTemplate("Invalid: ${'$'}value").addConstraintViolation()
                return false
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags buildConstraintViolationWithTemplate with method call result`() {
        val code = """
            fun isValid(obj: Any, ctx: ConstraintValidatorContext): Boolean {
                ctx.buildConstraintViolationWithTemplate(obj.toString()).addConstraintViolation()
                return false
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores buildConstraintViolationWithTemplate with literal message`() {
        val code = """
            fun isValid(value: String, context: ConstraintValidatorContext): Boolean {
                context.buildConstraintViolationWithTemplate("Value must be positive").addConstraintViolation()
                return false
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on InsecureCookie fixture`() {
        val code = """
            fun cookie(token: String) = NewCookie("session", token)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
