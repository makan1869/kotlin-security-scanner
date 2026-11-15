package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A02 — Cryptographic Failures (Improper Signature Verification / CWE-347)
 *
 * Configuring a Vert.x JWT key with `setAlgorithm("none")` accepts unsigned tokens, so anyone
 * can forge a JWT and the signature is never verified. Use a real algorithm (e.g. RS256/HS256).
 *
 * Non-compliant:
 *   PubSecKeyOptions().setAlgorithm("none")
 */
class VertxJwtNoneAlgorithmRule(config: Config) : SecurityRule(
    config,
    id = "VertxJwtNoneAlgorithm",
    description = "JWT algorithm set to \"none\" — unsigned tokens are accepted (signature not verified)",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text?.substringAfterLast(".") != "setAlgorithm") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtStringTemplateExpression ?: return
        if (arg.hasInterpolation()) return
        if (arg.rawValue().equals("none", ignoreCase = true)) {
            reportAt(expression, "setAlgorithm(\"none\") accepts unsigned JWTs — use RS256/ES256 (or HS256 with a strong secret)")
        }
    }
}
