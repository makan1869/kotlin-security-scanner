package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A05 — Security Misconfiguration
 *
 * HiddenHttpMethodFilter lets POST requests simulate PUT/DELETE/PATCH via a
 * _method parameter. Spring Boot 2.6+ disabled this filter by default because
 * it can bypass CSRF token checks that only guard specific HTTP methods.
 * Explicitly re-enabling it warrants review.
 *
 * Non-compliant:
 *   @Bean fun hiddenHttpMethodFilter() = HiddenHttpMethodFilter()
 */
class HttpMethodOverrideRule(config: Config) : SecurityRule(
    config,
    id = "HttpMethodOverride",
    description = "HiddenHttpMethodFilter re-enabled — can bypass method-specific CSRF checks",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee == DetectionPatterns.HTTP_METHOD_OVERRIDE_FILTER) {
            reportAt(
                expression,
                "HiddenHttpMethodFilter allows _method param override — disabled by default since Spring Boot 2.6",
            )
        }
    }
}
