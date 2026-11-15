package com.jasmin.security.detekt.a08

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusJsonbUnsafeDeserializationRuleTest {

    private val rule = QuarkusJsonbUnsafeDeserializationRule(Config.empty)

    @Test
    fun `flags Jsonb fromJson with Any type`() {
        val code = """
            fun deserialize(json: String) {
                val result = jsonb.fromJson(json, Any::class.java)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags Jsonb fromJson with Object type`() {
        val code = """
            fun deserialize(json: String) {
                val result = jsonb.fromJson(json, Object::class.java)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores Jsonb fromJson with concrete DTO type`() {
        val code = """
            fun deserialize(json: String): UserDto {
                return jsonb.fromJson(json, UserDto::class.java)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with QuarkusReflectionUnsafe fixture`() {
        val code = """
            @RegisterForReflection
            class MyClass(val data: Any)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
