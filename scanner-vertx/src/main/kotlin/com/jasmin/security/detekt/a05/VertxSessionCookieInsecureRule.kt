package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression

/**
 * OWASP A05 — Security Misconfiguration (Sensitive Cookie Without 'Secure' / CWE-614)
 *
 * `SessionHandler.create(store).setCookieSecureFlag(false)` sends the Vert.x session cookie
 * over plain HTTP, where it can be captured and the session hijacked. Enable the secure flag
 * so the session cookie is only sent over HTTPS.
 *
 * Non-compliant:
 *   SessionHandler.create(store).setCookieSecureFlag(false)
 */
class VertxSessionCookieInsecureRule(config: Config) : SecurityRule(
    config,
    id = "VertxSessionCookieInsecure",
    description = "SessionHandler.setCookieSecureFlag(false) — session cookie sent over plain HTTP",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text?.substringAfterLast(".") != "setCookieSecureFlag") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtConstantExpression ?: return
        if (arg.text != "false") return
        reportAt(expression, "setCookieSecureFlag(false) sends the session cookie over plain HTTP — call setCookieSecureFlag(true)")
    }
}
