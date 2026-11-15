package com.jasmin.security.detekt.a01

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusGraphQLNoAuthRuleTest {

    private val rule = QuarkusGraphQLNoAuthRule(Config.empty)

    @Test
    fun `flags GraphQLApi class without auth annotation`() {
        val code = """
            @GraphQLApi
            class ProductApi {
                fun products(): List<Product> = productService.findAll()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores GraphQLApi with RolesAllowed`() {
        val code = """
            @GraphQLApi
            @RolesAllowed("user")
            class ProductApi {
                fun products(): List<Product> = productService.findAll()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores GraphQLApi with Authenticated`() {
        val code = """
            @GraphQLApi
            @Authenticated
            class ProductApi {
                fun products(): List<Product> = productService.findAll()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores non-GraphQL class`() {
        val code = """
            @ApplicationScoped
            class ProductService {
                fun findAll(): List<Product> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
