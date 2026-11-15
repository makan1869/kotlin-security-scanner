package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// A state-changing Ktor route (POST/PUT/DELETE/PATCH) without reading the CSRF
// header or Origin is vulnerable to cross-site request forgery.
// Compliant:   rateLimited { post("/login") { ... } }
// Non-compliant: post("/login") { ... }  // in routing block without rate limiting
class KtorRateLimitingMissingRule(config: Config) : SecurityRule(
    config,
    id = "KtorRateLimitingMissing",
    description = "Ktor login/auth route without rate limiting — brute-force attack possible",
) {
    private val authKeywords = setOf("login", "auth", "token", "signin", "authenticate")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in setOf("post", "get", "put")) return
        val pathArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        val path = pathArg.trim('"')
        // Match path SEGMENTS by equality so `/authors` does not match `/auth`.
        val segments = path.split('/').filter { it.isNotEmpty() }
        if (segments.none { it in authKeywords }) return
        if (isInsideRateLimiting(expression)) return
        reportAt(
            expression,
            "Auth route $path without rate limiting — install RateLimit plugin or wrap in rateLimited{}",
        )
    }

    private fun isInsideRateLimiting(expression: KtCallExpression): Boolean {
        var current = expression.parent
        while (current != null) {
            if (current is KtCallExpression) {
                val callText = current.calleeExpression?.text ?: ""
                if ("rateLimited" in callText || "RateLimit" in callText) return true
            }
            current = current.parent
        }
        return false
    }
}
