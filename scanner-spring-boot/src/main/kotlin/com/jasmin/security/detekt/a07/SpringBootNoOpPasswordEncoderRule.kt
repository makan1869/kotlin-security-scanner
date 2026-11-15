package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

// OWASP A07 — Identification and Authentication Failures
// NoOpPasswordEncoder stores passwords as plaintext — any database read exposes all credentials.
// Compliant:   BCryptPasswordEncoder()
// Non-compliant: NoOpPasswordEncoder.getInstance()
class SpringBootNoOpPasswordEncoderRule(config: Config) : SecurityRule(
    config,
    id = "SpringBootNoOpPasswordEncoder",
    description = "NoOpPasswordEncoder stores passwords as cleartext — use BCryptPasswordEncoder",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "getInstance") return
        val dotExpr = expression.parent as? KtDotQualifiedExpression ?: return
        if (dotExpr.receiverExpression.text != "NoOpPasswordEncoder") return
        reportAt(
            dotExpr,
            "NoOpPasswordEncoder.getInstance() stores passwords as plaintext — use BCryptPasswordEncoder()",
        )
    }
}
