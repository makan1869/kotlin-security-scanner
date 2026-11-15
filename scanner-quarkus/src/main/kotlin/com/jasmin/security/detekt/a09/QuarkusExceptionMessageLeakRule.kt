package com.jasmin.security.detekt.a09

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A09 — Security Logging and Monitoring Failures
// Returning exception.message in the HTTP response reveals internal class names,
// SQL queries, and file paths — aids reconnaissance attacks.
// Compliant:   Response.serverError().entity("Internal error").build()
// Non-compliant: Response.serverError().entity(e.message).build()
class QuarkusExceptionMessageLeakRule(config: Config) : SecurityRule(
    config,
    id = "QuarkusExceptionMessageLeak",
    description = "Exception message returned in JAX-RS Response — exposes internal details to callers",
) {
    // A left boundary (?<![A-Za-z0-9_$]) ensures the receiver is a standalone identifier,
    // so "service.message" / "cache.toString()" do NOT match inside a longer identifier —
    // only bare "e", "ex", "exception", or "it" receivers are flagged.
    private val exceptionLeakPatterns = listOf(
        Regex("""(?<![A-Za-z0-9_$])ex\.(message|localizedMessage|stackTraceToString|toString)\b"""),
        Regex("""(?<![A-Za-z0-9_$])e\.(message|localizedMessage|stackTraceToString|toString)\b"""),
        Regex("""(?<![A-Za-z0-9_$])exception\.(message|localizedMessage|stackTraceToString|toString)\b"""),
        Regex("""(?<![A-Za-z0-9_$])it\.(message|localizedMessage|stackTraceToString|toString)\b"""),
    )

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val isExceptionMapper = function.annotationEntries.any {
            it.shortName?.asString() in setOf("ExceptionMapper", "ServerExceptionMapper", "Provider")
        }
        if (!isExceptionMapper) return
        val bodyText = function.bodyExpression?.text ?: return
        if (exceptionLeakPatterns.none { it.containsMatchIn(bodyText) }) return
        reportAt(
            function,
            "Exception mapper returning exception details — use a generic error message",
        )
    }
}
