package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtBinaryExpression

/**
 * OWASP A05 — Security Misconfiguration (Information Exposure Through Debug Info / CWE-489)
 *
 * developmentMode = true makes Ktor return full stack traces to clients and enables
 * class auto-reloading. Shipped to production it leaks internal details and hurts
 * performance. Gate it behind an environment check, never hardcode true.
 *
 * Non-compliant:
 *   environment { developmentMode = true }
 */
class KtorDevelopmentModeRule(config: Config) : SecurityRule(
    config,
    id = "KtorDevelopmentMode",
    description = "developmentMode = true leaks stack traces to clients — disable it in production",
) {
    override fun visitBinaryExpression(expression: KtBinaryExpression) {
        super.visitBinaryExpression(expression)
        if (expression.operationReference.text != "=") return
        val target = expression.left?.text ?: return
        if (!target.endsWith("developmentMode")) return
        if (expression.right?.text != "true") return
        reportAt(expression, "developmentMode = true exposes stack traces — set it from the environment, default false")
    }
}
