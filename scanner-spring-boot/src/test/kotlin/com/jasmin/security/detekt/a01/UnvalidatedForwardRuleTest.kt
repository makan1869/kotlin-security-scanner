package com.jasmin.security.detekt.a01

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class UnvalidatedForwardRuleTest {

    private val rule = UnvalidatedForwardRule(Config.empty)

    @Test
    fun `flags getRequestDispatcher with variable path`() {
        val code = """
            fun forward(request: HttpServletRequest, response: HttpServletResponse) {
                val page = request.getParameter("page")
                request.getRequestDispatcher(page).forward(request, response)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags getRequestDispatcher with string interpolation`() {
        val code = """
            fun forward(request: HttpServletRequest, response: HttpServletResponse, page: String) {
                request.getRequestDispatcher("/views/${'$'}page").forward(request, response)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores getRequestDispatcher with string literal`() {
        val code = """
            fun forward(request: HttpServletRequest, response: HttpServletResponse) {
                request.getRequestDispatcher("/internal/safe-page.jsp").forward(request, response)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `does not interfere with open redirect code`() {
        val code = """
            @GetMapping("/redirect")
            fun redirect(url: String): String = "redirect:${'$'}url"
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
