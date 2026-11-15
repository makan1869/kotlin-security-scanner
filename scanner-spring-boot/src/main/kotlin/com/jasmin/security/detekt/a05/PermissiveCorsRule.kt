package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: PERMISSIVE_CORS — OWASP A05
class PermissiveCorsRule(config: Config = Config.empty) : SecurityRule(
    config,
    id = "PermissiveCors",
    description = "CORS allows all origins ('*') — restrict to known domains in production (OWASP A05)",
) {
    private val corsMethodNames = setOf("allowedOrigins", "allowedOriginPatterns", "addAllowedOrigin")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in corsMethodNames) return
        if (hasWildcardArgument(expression)) {
            reportAt(expression, "'$callee(\"*\")' allows any origin — restrict to explicit domains")
        }
    }

    private fun hasWildcardArgument(expression: KtCallExpression) =
        expression.valueArguments.any { arg ->
            val str = arg.getArgumentExpression() as? KtStringTemplateExpression ?: return@any false
            str.isLiteral() && str.rawValue() == "*"
        }
}
