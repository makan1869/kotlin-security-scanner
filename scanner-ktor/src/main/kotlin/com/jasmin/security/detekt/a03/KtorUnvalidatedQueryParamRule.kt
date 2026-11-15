package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.lexer.KtTokens
import org.jetbrains.kotlin.psi.KtArrayAccessExpression
import org.jetbrains.kotlin.psi.KtPostfixExpression

// OWASP A03 — Injection
// call.parameters["id"]!! force-unwraps a nullable query parameter. A request
// without that parameter crashes the handler with a NullPointerException,
// causing a 500 response that leaks stack details and enables DoS.
// Always validate with safe-call + elvis: val id = call.parameters["id"] ?: return call.respond(BadRequest)
// Compliant:   val id = call.parameters["id"] ?: return call.respond(HttpStatusCode.BadRequest)
// Non-compliant: val id = call.parameters["id"]!!
class KtorUnvalidatedQueryParamRule(config: Config) : SecurityRule(
    config,
    id = "KtorUnvalidatedQueryParam",
    description = "call.parameters[\"...\"]!! force-unwrap — missing parameter causes unhandled 500; use ?: return call.respond(BadRequest)",
) {
    @Suppress("ReturnCount")
    override fun visitPostfixExpression(expression: KtPostfixExpression) {
        super.visitPostfixExpression(expression)
        if (expression.operationToken != KtTokens.EXCLEXCL) return
        val base = expression.baseExpression as? KtArrayAccessExpression ?: return
        val arrayText = base.arrayExpression?.text ?: return
        if ("parameters" !in arrayText) return
        reportAt(
            expression,
            "Force-unwrap on call.parameters — use ?: return call.respond(HttpStatusCode.BadRequest) instead of !!",
        )
    }
}
