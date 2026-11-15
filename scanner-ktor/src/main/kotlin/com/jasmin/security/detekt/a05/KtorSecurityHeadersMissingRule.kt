package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// install(DefaultHeaders) without X-Frame-Options and X-Content-Type-Options
// leaves the app exposed to clickjacking and MIME sniffing attacks.
// Compliant:   install(DefaultHeaders) { header("X-Frame-Options", "DENY") }
// Non-compliant: install(DefaultHeaders)  // no security headers configured
class KtorSecurityHeadersMissingRule(config: Config) : SecurityRule(
    config,
    id = "KtorSecurityHeadersMissing",
    description = "Ktor DefaultHeaders without X-Frame-Options — app is vulnerable to clickjacking",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.KTOR_INSTALL) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        if (firstArg != "DefaultHeaders") return
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: ""
        if ("X-Frame-Options" in lambdaText) return
        reportAt(
            expression,
            "install(DefaultHeaders) missing X-Frame-Options — add header(\"X-Frame-Options\", \"DENY\")",
        )
    }
}
