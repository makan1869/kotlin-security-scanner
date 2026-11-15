package com.jasmin.security.detekt.a10

import com.jasmin.security.detekt.core.DetectionPatterns.SSRF_CONSTRUCTORS
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: URLCONNECTION_SSRF_FD — OWASP A10
class SsrfRule(config: Config = Config.empty) : SecurityRule(
    config,
    id = "Ssrf",
    description = "URL/URI built with a non-literal — validate and allowlist user-supplied URLs (OWASP A10)",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in SSRF_CONSTRUCTORS) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg is KtStringTemplateExpression && firstArg.isLiteral()) return
        reportAt(expression, "'$callee' constructed with a dynamic value — allowlist permitted hosts to prevent SSRF")
    }
}
