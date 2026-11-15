package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A03 — Injection (LDAP)
 * FindSecBugs: LDAP_INJECTION
 *
 * Flags LDAP operations (search, bind, lookup) where a string argument
 * contains interpolation. LDAP special characters in user input can alter
 * the filter logic, enabling authentication bypass and data exfiltration.
 *
 * Compliant:
 *   val filter = "(uid={0})"
 *   ctx.search("ou=users", filter, SearchControls())   // parameterised
 *
 * Non-compliant:
 *   ctx.search("ou=users", "(uid=${'$'}username)", controls)        // interpolated filter
 *   ctx.search("ou=users", "(uid=" + username + ")", controls)   // concatenated filter
 */
class LdapInjectionRule(config: Config) : SecurityRule(
    config,
    id = "LdapInjection",
    description = "LDAP operation with interpolated argument — escape input or use parameterised filters",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in DetectionPatterns.LDAP_OPERATION_METHODS) return
        if (hasInterpolatedStringArg(expression)) {
            reportAt(
                expression,
                "LDAP $callee() uses an interpolated filter — escape user input with LdapEncoder.filterEncode()",
            )
        }
    }

    private fun hasInterpolatedStringArg(expression: KtCallExpression) =
        expression.valueArguments.any { arg ->
            when (val e = arg.getArgumentExpression()) {
                is KtStringTemplateExpression -> e.hasInterpolation()
                else -> e.isDynamicStringConcat()
            }
        }
}
