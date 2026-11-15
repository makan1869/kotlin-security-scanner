package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A01 — Broken Access Control
// A webSocket() handler without an authenticate {} parent accepts connections from
// any client, including unauthenticated ones. Authentication must be enforced at
// the protocol level before the WebSocket upgrade is accepted.
// Compliant:   routing { authenticate("jwt") { webSocket("/chat") { ... } } }
// Non-compliant: routing { webSocket("/chat") { ... } }
class KtorWebSocketNoAuthRule(config: Config) : SecurityRule(
    config,
    id = "KtorWebSocketNoAuth",
    description = "webSocket() handler without authenticate{} — wrap with authenticate(\"provider\") to require credentials",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "webSocket") return
        if (isInsideAuthenticate(expression)) return
        reportAt(
            expression,
            "webSocket() without authenticate{} — all WebSocket connections are unauthenticated",
        )
    }

    private fun isInsideAuthenticate(expression: KtCallExpression): Boolean {
        var current = expression.parent
        while (current != null) {
            if (current is KtCallExpression) {
                val callee = current.calleeExpression?.text ?: ""
                if (callee == "authenticate") return true
                if (callee == "routing") return false
            }
            current = current.parent
        }
        return false
    }
}
