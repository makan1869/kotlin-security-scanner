package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: HARD_CODE_KEY
 *
 * A hardcoded secret in JwtAuthFilter allows anyone with source access
 * to forge valid JWTs and impersonate any user.
 *
 * Compliant:
 *   JwtAuthFilter.Builder<User>().setSecretProvider { System.getenv("JWT_SECRET") }
 *
 * Non-compliant:
 *   JwtAuthFilter.Builder<User>().setSecretProvider { "hardcoded-jwt-secret" }
 */
class DropwizardUnencryptedJwtSecretRule(config: Config) : SecurityRule(
    config,
    id = "DropwizardUnencryptedJwtSecret",
    description = "JwtAuthFilter secret provider returns a literal — use environment variable or key store",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.DW_JWT_SECRET_PROVIDER) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        val isSafe = firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()
        if (!isSafe) return
        reportAt(
            expression,
            "setSecretProvider() with hardcoded literal — load the JWT secret from an environment variable",
        )
    }
}
