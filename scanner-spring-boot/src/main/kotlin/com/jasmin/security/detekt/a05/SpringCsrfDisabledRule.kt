package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

// FindSecBugs: SPRING_CSRF_PROTECTION_DISABLED — OWASP A05
class SpringCsrfDisabledRule(config: Config = Config.empty) : SecurityRule(
    config,
    id = "SpringCsrfDisabled",
    description = "CSRF protection disabled — let Spring generate tokens instead (OWASP A05)",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        when {
            isCsrfLambdaDisable(callee, expression) -> reportAt(expression, description)
            isFluentDisableOnCsrf(callee, expression) -> reportAt(expression, description)
            isCsrfMethodReference(callee, expression) -> reportAt(expression, description)
        }
    }

    private fun isCsrfLambdaDisable(callee: String, expression: KtCallExpression) =
        callee == "csrf" && expression.lambdaArguments.any { it.text.contains("disable") }

    @Suppress("ReturnCount")
    private fun isFluentDisableOnCsrf(callee: String, expression: KtCallExpression): Boolean {
        if (callee != "disable") return false
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression ?: return false
        return receiver.text.contains("csrf")
    }

    private fun isCsrfMethodReference(callee: String, expression: KtCallExpression) =
        callee == "csrf" && expression.valueArguments.any { it.text.contains("disable") }
}
