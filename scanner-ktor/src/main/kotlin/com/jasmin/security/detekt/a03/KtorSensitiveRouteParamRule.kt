package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// OWASP A03 — Injection
// call.parameters["id"] used directly in SQL/LDAP string via interpolation
// is an injection point. Always validate and use parameterized queries.
// Compliant:   val id = call.parameters["id"]?.toLongOrNull() ?: return; Users.select { Users.id eq id }
// Non-compliant: exec("SELECT * FROM users WHERE id = ${call.parameters["id"]}")
class KtorSensitiveRouteParamRule(config: Config) : SecurityRule(
    config,
    id = "KtorSensitiveRouteParam",
    description = "call.parameters value used in SQL/exec string template — use parameterized queries",
) {
    private val dangerousCalls = setOf("exec", "query", "createNativeQuery", "createQuery")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in dangerousCalls) return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression() ?: return
        if (firstArg !is KtStringTemplateExpression || !firstArg.hasInterpolation()) return
        if ("call.parameters" !in firstArg.text && "parameters[" !in firstArg.text) return
        reportAt(
            expression,
            "call.parameters in SQL string — extract, validate, and use parameterized query",
        )
    }
}
