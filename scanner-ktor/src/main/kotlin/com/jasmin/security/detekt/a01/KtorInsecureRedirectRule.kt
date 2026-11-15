package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A01 — Broken Access Control
 * call.respondRedirect with a non-literal URL allows an attacker to redirect users
 * to a malicious site by controlling the redirect target.
 */
class KtorInsecureRedirectRule(config: Config) : SecurityRule(
    config,
    id = "KtorInsecureRedirect",
    description = "call.respondRedirect with non-literal URL — validate target to prevent open redirect",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != DetectionPatterns.KTOR_RESPOND_REDIRECT) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()) return
        reportAt(
            expression,
            "call.respondRedirect with non-literal URL — validate the redirect target to prevent open redirect",
        )
    }
}
