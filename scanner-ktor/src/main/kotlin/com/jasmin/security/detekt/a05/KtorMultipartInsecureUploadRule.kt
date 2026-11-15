package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A05 — Security Misconfiguration
// receiveMultipart() without a maxFileSize argument accepts arbitrarily large files,
// enabling resource exhaustion. Ktor's default maxFileSize is Long.MAX_VALUE.
// Compliant:   call.receiveMultipart(maxFileSize = 10 * 1024 * 1024L)   // 10 MB
// Non-compliant: call.receiveMultipart()
class KtorMultipartInsecureUploadRule(config: Config) : SecurityRule(
    config,
    id = "KtorMultipartInsecureUpload",
    description = "receiveMultipart() without maxFileSize — accepts arbitrarily large uploads (resource exhaustion)",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "receiveMultipart") return
        val hasMaxFileSize = expression.valueArguments.any {
            val name = it.getArgumentName()?.asName?.asString()
            name == "maxFileSize" || "maxFileSize" in (it.text ?: "")
        }
        if (hasMaxFileSize) return
        reportAt(
            expression,
            "receiveMultipart() without maxFileSize limit — add maxFileSize = 10 * 1024 * 1024L to cap uploads at 10 MB",
        )
    }
}
