package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A05 — Security Misconfiguration (CSRF / CWE-352)
 *
 * csrf { ignoringRequestMatchers("/api/...") } turns CSRF protection off for the
 * matched paths. State-changing endpoints behind those matchers become forgeable.
 * Exclude only stateless, token-authenticated APIs — and review every matcher.
 *
 * Non-compliant:
 *   http.csrf { it.ignoringRequestMatchers(apiPathPattern) }
 */
class SpringCsrfIgnoringMatchersRule(config: Config = Config.empty) : SecurityRule(
    config,
    id = "SpringCsrfIgnoringMatchers",
    description = "CSRF protection excluded for matched paths — those endpoints become forgeable",
) {
    private val ignoringMethods = setOf("ignoringRequestMatchers", "ignoringAntMatchers")

    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in ignoringMethods) return
        reportAt(
            expression,
            "$callee() disables CSRF for the matched paths — exclude only stateless token-authenticated APIs",
        )
    }
}
