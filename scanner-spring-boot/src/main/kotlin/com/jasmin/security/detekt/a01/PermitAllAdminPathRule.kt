package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

// OWASP A01 — Broken Access Control
// permitAll() on admin/actuator paths removes authentication entirely.
// Compliant: .requestMatchers("/admin/users").hasRole("ADMIN")
// Non-compliant: .requestMatchers("/admin/users").permitAll()
class PermitAllAdminPathRule(config: Config) : SecurityRule(
    config,
    id = "PermitAllAdminPath",
    description = "permitAll() on admin/actuator path — unauthenticated access to privileged endpoints",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "permitAll") return
        // Only this call's own receiver chain, e.g. it.requestMatchers("/admin/**") in
        // it.requestMatchers("/admin/**").permitAll() — not sibling statements nearby.
        val chainText = (expression.parent as? KtDotQualifiedExpression)?.receiverExpression?.text ?: return
        val hasSensitivePath = DetectionPatterns.ADMIN_PATHS.any { it in chainText }
        if (!hasSensitivePath) return
        reportAt(expression, "permitAll() on admin/actuator path — use hasRole('ADMIN') or hasAuthority('SCOPE_admin')")
    }
}
