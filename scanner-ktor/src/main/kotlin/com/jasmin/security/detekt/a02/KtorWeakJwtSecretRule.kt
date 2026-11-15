package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A02 — Cryptographic Failures
// jwt { verifier(JWT.require(Algorithm.HMAC256("literal"))) } embeds the signing
// secret as a constant. Short or common secrets are brute-forceable.
// Compliant:   Algorithm.HMAC256(System.getenv("JWT_SECRET"))
// Non-compliant: Algorithm.HMAC256("my-secret")
class KtorWeakJwtSecretRule(config: Config) : SecurityRule(
    config,
    id = "KtorWeakJwtSecret",
    description = "Ktor JWT verifier with hardcoded HMAC secret — use environment variable",
) {
    private val hmacMethods = setOf("HMAC256", "HMAC384", "HMAC512")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in hmacMethods && !hmacMethods.any { callee.endsWith(".$it") }) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtStringTemplateExpression || firstArg.hasInterpolation()) return
        val secret = firstArg.text.trim('"')
        if (secret.isBlank() || secret.startsWith("\${")) return
        reportAt(expression, "HMAC secret is a string literal — use System.getenv(\"JWT_SECRET\")")
    }
}
