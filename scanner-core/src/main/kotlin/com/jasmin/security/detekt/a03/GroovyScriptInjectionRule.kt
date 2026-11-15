package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtCallableDeclaration
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression
import org.jetbrains.kotlin.psi.KtFile
import org.jetbrains.kotlin.psi.KtNameReferenceExpression
import org.jetbrains.kotlin.psi.KtParameter
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtStringTemplateExpression
import org.jetbrains.kotlin.psi.psiUtil.collectDescendantsOfType

/**
 * OWASP A03 — Injection (Groovy / ScriptEngine)
 * FindSecBugs: GROOVY_SHELL
 *
 * Flags GroovyShell.evaluate() and ScriptEngine.eval() calls where the script
 * argument is not a string literal. Executing attacker-supplied Groovy or script
 * engine code enables arbitrary code execution on the JVM host.
 *
 * Compliant:
 *   shell.evaluate("println 'hello'")          // literal — safe
 *
 * Non-compliant:
 *   shell.evaluate(userScript)                 // variable — RCE risk
 *   engine.eval("println '${'$'}userInput'")   // interpolated — RCE risk
 */
class GroovyScriptInjectionRule(config: Config) : SecurityRule(
    config,
    id = "GroovyScriptInjection",
    description = "Script execution with non-literal source — user-controlled scripts enable RCE",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.SCRIPT_EVAL_METHODS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()) return
        if (!callsScriptEngine(expression)) return
        reportAt(
            expression,
            "$callee() with dynamic script source — never pass user input to a script engine",
        )
    }

    /**
     * True when the call goes to a script engine: the file imports one, the receiver names an engine
     * type, or the receiver is a variable declared in this file with an engine type or initializer.
     */
    private fun callsScriptEngine(call: KtCallExpression): Boolean {
        val file = call.containingKtFile
        val qualified = call.parent as? KtDotQualifiedExpression
        val receiver = qualified?.takeIf { it.selectorExpression == call }?.receiverExpression
        return importsEngine(file) ||
            (receiver is KtNameReferenceExpression && declaresEngine(file, receiver.getReferencedName())) ||
            (receiver != null && namesEngine(receiver.text))
    }

    private fun importsEngine(file: KtFile): Boolean = file.importDirectives.any { directive ->
        val path = directive.importPath?.pathStr.orEmpty()
        DetectionPatterns.SCRIPT_ENGINE_IMPORT_PREFIXES.any { path.startsWith(it) }
    }

    private fun declaresEngine(file: KtFile, name: String): Boolean = file
        .collectDescendantsOfType<KtCallableDeclaration> { it.name == name && (it is KtProperty || it is KtParameter) }
        .any { declaration ->
            namesEngine(declaration.typeReference?.text.orEmpty()) ||
                namesEngine((declaration as? KtProperty)?.initializer?.text.orEmpty())
        }

    private fun namesEngine(text: String): Boolean = DetectionPatterns.SCRIPT_ENGINE_TYPES.any { text.contains(it) }
}
