package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns.SQL_STATEMENT_PATTERNS
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtBinaryExpression
import org.jetbrains.kotlin.psi.KtStringTemplateEntryWithExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: SQL_INJECTION_JPA, SQL_INJECTION_SPRING_JDBC — OWASP A03
class SqlInjectionRule(config: Config = Config.empty) : SecurityRule(
    config,
    id = "SqlInjection",
    description = "SQL built with string interpolation or concatenation — use named parameters (e.g. :param)",
) {
    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.isLiteral()) return
        if (looksLikeSql(skeletonOf(expression))) {
            reportAt(expression, "String interpolation in SQL query — use :namedParam or ? placeholders")
        }
    }

    @Suppress("ReturnCount")
    override fun visitBinaryExpression(expression: KtBinaryExpression) {
        super.visitBinaryExpression(expression)
        if (expression.operationReference.text != "+") return
        val left = expression.left ?: return
        if (expression.right is KtStringTemplateExpression) return
        val leftText = (left as? KtStringTemplateExpression)?.let(::skeletonOf) ?: left.text
        if (!looksLikeSql(leftText)) return
        reportAt(expression, "String concatenation in SQL query — use :namedParam or ? placeholders")
    }

    /** The string's literal text, with each interpolated value replaced by a `?` placeholder. */
    private fun skeletonOf(template: KtStringTemplateExpression): String =
        template.entries.joinToString("") { if (it is KtStringTemplateEntryWithExpression) "?" else it.text }

    private fun looksLikeSql(text: String) = SQL_STATEMENT_PATTERNS.any { it.containsMatchIn(text) }
}
