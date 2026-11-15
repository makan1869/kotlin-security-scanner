package com.jasmin.security.detekt.a03

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class GroovyScriptInjectionRuleTest {

    private val rule = GroovyScriptInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags GroovyShell evaluate with variable script`() {
        val code = """
            fun run(userScript: String) = GroovyShell().evaluate(userScript)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags GroovyShell evaluate with interpolated script`() {
        val code = """
            fun run(expr: String) = GroovyShell().evaluate("println '${'$'}expr'")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags ScriptEngine eval with variable`() {
        val code = """
            fun run(code: String) {
                val engine = ScriptEngineManager().getEngineByName("groovy")
                engine.eval(code)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags evaluate with method call result`() {
        val code = """
            fun run(req: HttpServletRequest) =
                GroovyShell().evaluate(req.getParameter("script"))
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores evaluate with literal script`() {
        val code = """
            fun greet() = GroovyShell().evaluate("println 'hello world'")
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores eval with literal script`() {
        val code = """
            fun calc() {
                val engine = ScriptEngineManager().getEngineByName("groovy")
                engine.eval("1 + 1")
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on ReflectionInjection fixture`() {
        val code = """
            fun load(className: String): Class<*> = Class.forName(className)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Only calls to a script engine ────────────────────────────────────────

    @Test
    fun `flags evaluate on a receiver of any name when the file imports a script engine`() {
        val code = """
            import groovy.lang.GroovyShell

            fun run(shell: Any, script: String) = shell.evaluate(script)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags eval on a parameter declared as a script engine`() {
        val code = """
            fun run(engine: ScriptEngine, code: String) = engine.eval(code)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores evaluate on an object that is not a script engine`() {
        val code = """
            fun ready(checks: List<String>) = CiReadinessEvaluator.evaluate(checks, required)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores evaluate on a variable that is not a script engine`() {
        val code = """
            class Gate(private val evaluator: ApprovalEvaluator) {
                fun decide(facts: Facts) = evaluator.evaluate(facts)
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores a local function called evaluate`() {
        val code = """
            fun evaluate(input: String) = input.length
            fun check(value: String) = evaluate(value)
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
