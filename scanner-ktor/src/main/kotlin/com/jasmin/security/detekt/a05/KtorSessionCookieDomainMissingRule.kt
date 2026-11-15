package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// A Ktor cookie session without cookie.domain allows the browser to send the session
// cookie to all subdomains, including attacker-controlled ones (subdomain takeover).
// Compliant:   cookie<MySession>("S") { cookie.domain = "app.example.com" }
// Non-compliant: cookie<MySession>("SESSION") { }  // no domain restriction
class KtorSessionCookieDomainMissingRule(config: Config) : SecurityRule(
    config,
    id = "KtorSessionCookieDomainMissing",
    description = "Ktor session cookie without domain restriction — vulnerable to subdomain takeover",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.KTOR_INSTALL) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        if (firstArg != DetectionPatterns.KTOR_SESSIONS_FEATURE) return
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: return
        if ("cookie" !in lambdaText) return
        if ("cookie.domain" in lambdaText || ".domain" in lambdaText) return
        reportAt(
            expression,
            "Session cookie without .domain — set cookie.domain = \"app.example.com\" in Sessions config",
        )
    }
}
