package com.jasmin.security.detekt.core

import dev.detekt.api.Config
import dev.detekt.api.Entity
import dev.detekt.api.Finding
import dev.detekt.api.Rule
import dev.detekt.api.RuleName
import org.jetbrains.kotlin.psi.KtAnnotated
import org.jetbrains.kotlin.psi.KtAnnotationEntry
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtElement
import org.jetbrains.kotlin.psi.KtExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * Base class for all custom security rules.
 *
 * Provides small, named helpers so rule logic reads declaratively —
 * describing WHAT is checked rather than HOW the AST is traversed.
 * Keep this lean: only add a helper when two or more rules share the need.
 */
abstract class SecurityRule(
    config: Config,
    private val id: String,
    description: String,
) : Rule(config, description) {

    // ── Identity ────────────────────────────────────────────────────────────────
    //
    // detekt 2 names a rule after its class by default ("SqlInjectionRule"). The rule ids in
    // config and reports predate that ("SqlInjection"), so keep them stable.
    //
    // Activation is not decided here: detekt 2 only runs rules listed in config, and every
    // module ships src/main/resources/config/config.yml with its rules active by default.
    override val ruleName: RuleName
        get() = RuleName(id)

    // ── Reporting ─────────────────────────────────────────────────────────────

    protected fun reportAt(node: KtElement, message: String) {
        report(Finding(Entity.from(node), decorate(message)))
    }

    /** Appends the CWE id and remediation hint registered for this rule, when there are any. */
    protected fun decorate(message: String): String {
        val cwe = CweMapping.forRule(id)
        val fix = RemediationHints.forRule(id)
        val withCwe = if (cwe != null) "$message [$cwe]" else message
        return if (fix != null) "$withCwe — Fix: $fix" else withCwe
    }

    // ── AST traversal ─────────────────────────────────────────────────────────

    /** Walk up [levels] parent steps and return that ancestor (or null). */
    protected fun KtElement.ancestor(levels: Int): KtElement? {
        var current: KtElement? = this
        repeat(levels) { current = current?.parent as? KtElement }
        return current
    }

    /** True when this string contains no interpolated expressions. */
    protected fun KtStringTemplateExpression.isLiteral(): Boolean = !hasInterpolation()

    /** Raw string value without surrounding quotes. */
    protected fun KtStringTemplateExpression.rawValue(): String =
        text.removeSurrounding("\"").removeSurrounding("'")

    // ── Dynamic string building ────────────────────────────────────────────────

    /**
     * True when this expression builds a string by '+'-concatenation that mixes a
     * string literal with at least one non-constant operand — e.g. `"(uid=" + name + ")"`.
     *
     * Precise by design: a pure constant concatenation (`"a" + "b"`) returns false (no
     * false positive), and a non-string `+` (no string literal anywhere) returns false.
     * Use alongside `KtStringTemplateExpression.hasInterpolation()` to cover both ways of
     * splicing untrusted input into a query/filter without binding-context dataflow.
     */
    protected fun KtExpression?.isDynamicStringConcat(): Boolean {
        if (this !is KtBinaryExpression || operationReference.text != "+") return false
        return containsStringLiteral(this) && !isAllConstantStrings(this)
    }

    private fun containsStringLiteral(expr: KtExpression?): Boolean = when (expr) {
        is KtStringTemplateExpression -> true
        is KtBinaryExpression -> containsStringLiteral(expr.left) || containsStringLiteral(expr.right)
        else -> false
    }

    private fun isAllConstantStrings(expr: KtExpression?): Boolean = when (expr) {
        is KtStringTemplateExpression -> !expr.hasInterpolation()
        is KtBinaryExpression ->
            expr.operationReference.text == "+" &&
                isAllConstantStrings(expr.left) && isAllConstantStrings(expr.right)
        else -> false
    }

    // ── Annotation inspection ─────────────────────────────────────────────────

    /** Short name of each annotation on this element (e.g. "GetMapping"). */
    protected fun KtAnnotated.annotationNames(): Set<String> =
        annotationEntries.mapNotNull { it.shortName() }.toSet()

    private fun KtAnnotationEntry.shortName(): String? =
        shortName?.asString()
}
