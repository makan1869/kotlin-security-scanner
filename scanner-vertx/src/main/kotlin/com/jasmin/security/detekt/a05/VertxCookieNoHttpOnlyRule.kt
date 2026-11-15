package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtConstantExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A05 — Security Misconfiguration (Cookie Without 'HttpOnly' / CWE-1004)
 *
 * `.setHttpOnly(false)` on a Vert.x cookie lets client-side JavaScript read it, so an XSS flaw
 * can steal the session/auth cookie. Keep HttpOnly on for cookies the browser shouldn't expose
 * to scripts.
 *
 * Non-compliant:
 *   Cookie.cookie("session", id).setHttpOnly(false)
 */
class VertxCookieNoHttpOnlyRule(config: Config) : SecurityRule(
    config,
    id = "VertxCookieNoHttpOnly",
    description = "Vert.x cookie setHttpOnly(false) — readable by JavaScript (XSS cookie theft)",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text?.substringAfterLast(".") != "setHttpOnly") return
        val arg = expression.valueArguments.firstOrNull()?.getArgumentExpression() as? KtConstantExpression ?: return
        if (arg.text != "false") return
        val receiver = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        if (!receiver.contains("ookie")) return
        reportAt(expression, "Cookie.setHttpOnly(false) exposes the cookie to JavaScript — call .setHttpOnly(true)")
    }
}
