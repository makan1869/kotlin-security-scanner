package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A01 — Broken Access Control (Unvalidated Forward)
 *
 * request.getRequestDispatcher(userInput).forward() redirects the request
 * to an internal resource chosen by the attacker. This can bypass access
 * controls on protected internal pages.
 *
 * Compliant:
 *   request.getRequestDispatcher("/internal/safe-page.jsp").forward(req, res)
 *
 * Non-compliant:
 *   request.getRequestDispatcher(request.getParameter("page")).forward(req, res)
 */
class UnvalidatedForwardRule(config: Config) : SecurityRule(
    config,
    id = "UnvalidatedForward",
    description = "getRequestDispatcher() called with non-literal path — enables unvalidated internal forward",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "getRequestDispatcher") return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()) return
        reportAt(expression, "Validate forward path against an allowlist — never forward to user-supplied paths")
    }
}
