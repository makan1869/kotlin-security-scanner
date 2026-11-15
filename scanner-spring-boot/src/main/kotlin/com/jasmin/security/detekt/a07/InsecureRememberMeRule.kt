package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures
 *
 * rememberMe().key("hardcoded") signs persistent login cookies with a
 * static secret. Any developer with repo access can forge remember-me
 * cookies for arbitrary users. The secret must come from an environment
 * variable or secret store, not a string literal.
 *
 * Compliant:
 *   http.rememberMe().key(System.getenv("REMEMBER_ME_KEY"))
 *
 * Non-compliant:
 *   http.rememberMe().key("myStaticRememberMeKey")
 */
class InsecureRememberMeRule(config: Config) : SecurityRule(
    config,
    id = "InsecureRememberMe",
    description = "rememberMe().key() uses a hardcoded literal — cookie signing secret must come from environment",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "key") return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtStringTemplateExpression || firstArg.hasInterpolation()) return
        if ("rememberMe" !in (expression.parent?.text ?: "")) return
        reportAt(
            expression,
            "rememberMe key is a string literal — use System.getenv(\"REMEMBER_ME_KEY\") or a generated secret",
        )
    }
}
