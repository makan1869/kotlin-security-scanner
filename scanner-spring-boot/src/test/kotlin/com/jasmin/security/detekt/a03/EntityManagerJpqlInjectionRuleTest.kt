package com.jasmin.security.detekt.a03

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class EntityManagerJpqlInjectionRuleTest {

    private val rule = EntityManagerJpqlInjectionRule(Config.empty)

    @Test
    fun `flags createQuery with interpolated string`() {
        val code = """
            class UserRepo(private val em: EntityManager) {
                fun findByName(name: String) =
                    em.createQuery("SELECT u FROM User u WHERE u.name = '${'$'}name'")
                        .resultList
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags createNativeQuery with variable`() {
        val code = """
            class UserRepo(private val em: EntityManager) {
                fun findById(id: String): Any {
                    val sql = "SELECT * FROM users WHERE id = ${'$'}id"
                    return em.createNativeQuery(sql).singleResult
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores createQuery with pure string literal`() {
        val code = """
            class UserRepo(private val em: EntityManager) {
                fun findAll() =
                    em.createQuery("SELECT u FROM User u").resultList
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores createQuery with named parameter`() {
        val code = """
            class UserRepo(private val em: EntityManager) {
                fun findByName(name: String) =
                    em.createQuery("SELECT u FROM User u WHERE u.name = :name")
                        .setParameter("name", name)
                        .resultList
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores createQuery built from constant string concatenation`() {
        val code = """
            class UserRepo(private val em: EntityManager) {
                fun findAll() =
                    em.createQuery("SELECT u " + "FROM User u").resultList
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with SpEL injection code`() {
        val code = """
            class Service(private val parser: SpelExpressionParser) {
                fun evaluate(expr: String) = parser.parseExpression("user.name")
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
