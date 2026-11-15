package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// install(ForwardedHeaders) or install(XForwardedHeaders) unconditionally trusts
// X-Forwarded-For / Forwarded headers sent by the client. An attacker can spoof
// the originating IP, bypassing IP-based rate limiting or access controls.
// Only enable when requests actually come through a trusted reverse proxy.
// Compliant:   install(ForwardedHeaders) { trustProxyHeaders = listOf("10.0.0.1/24") }
// Non-compliant: install(ForwardedHeaders)
class KtorForwardedHeaderTrustRule(config: Config) : SecurityRule(
    config,
    id = "KtorForwardedHeaderTrust",
    description = "install(ForwardedHeaders) trusts client-supplied IP headers — restrict to known proxy CIDR ranges",
) {
    private val forwardedPlugins = setOf("ForwardedHeaders", "XForwardedHeaders")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "install") return
        val firstArg = expression.valueArguments.firstOrNull()?.getArgumentExpression()?.text ?: return
        if (firstArg !in forwardedPlugins) return
        // Compliant when the trailing config lambda restricts trust to known proxies.
        val lambdaText = expression.lambdaArguments.firstOrNull()?.text ?: ""
        if ("trustProxyHeaders" in lambdaText || "useFirstProxy" in lambdaText ||
            "useLastProxy" in lambdaText || "skipLastProxies" in lambdaText
        ) {
            return
        }
        reportAt(
            expression,
            "install($firstArg) without proxy restrictions — an attacker can spoof X-Forwarded-For to bypass IP-based controls",
        )
    }
}
