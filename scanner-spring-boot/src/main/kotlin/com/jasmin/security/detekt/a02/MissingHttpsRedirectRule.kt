package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtNamedFunction

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: INSECURE_CHANNEL
 *
 * A SecurityFilterChain bean that never calls requiresChannel() or
 * requiresSecure() allows HTTP traffic to reach protected endpoints.
 * Credentials and session tokens sent over HTTP are exposed in plaintext.
 *
 * Compliant:
 *   http.requiresChannel { it.anyRequest().requiresSecure() }
 *
 * Non-compliant:
 *   @Bean fun filterChain(http: HttpSecurity): SecurityFilterChain {
 *       http.authorizeHttpRequests { it.anyRequest().authenticated() }
 *       return http.build()  // no requiresChannel
 *   }
 */
class MissingHttpsRedirectRule(config: Config) : SecurityRule(
    config,
    id = "MissingHttpsRedirect",
    description = "SecurityFilterChain missing HTTPS — add requiresChannel { anyRequest().requiresSecure() }",
) {
    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val annotations = function.annotationEntries
            .mapNotNull { it.shortName?.asString() }.toSet()
        if ("Bean" !in annotations) return
        val returnType = function.typeReference?.text ?: return
        if ("SecurityFilterChain" !in returnType) return
        val body = function.bodyExpression?.text ?: return
        if ("requiresChannel" in body || "requiresSecure" in body) return
        reportAt(
            function,
            "SecurityFilterChain missing HTTPS redirect — add requiresChannel { anyRequest().requiresSecure() }",
        )
    }
}
