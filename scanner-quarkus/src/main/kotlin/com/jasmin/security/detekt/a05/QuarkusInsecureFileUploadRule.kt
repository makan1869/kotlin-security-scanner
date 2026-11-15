package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtNamedFunction

// OWASP A05 — Security Misconfiguration
// Using FileUpload.fileName() directly as the target path enables path traversal:
// a filename of "../../etc/cron.d/evil" overwrites arbitrary server files.
// Compliant:   val safe = UUID.randomUUID().toString() + extension
// Non-compliant: File(uploadDir, fileItem.fileName())
class QuarkusInsecureFileUploadRule(config: Config) : SecurityRule(
    config,
    id = "QuarkusInsecureFileUpload",
    description = "FileUpload.fileName() used as file path — path traversal risk",
) {
    private val pathContextKeywords = setOf("File(", "Paths.get", "resolve", "transferTo", "copyTo")

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val hasFormDataParam = function.valueParameters.any {
            val type = it.typeReference?.text ?: ""
            "FileUpload" in type || "FormData" in type || "MultipartBody" in type
        }
        if (!hasFormDataParam) return
        val bodyText = function.bodyExpression?.text ?: return
        if ("fileName()" !in bodyText && "name()" !in bodyText) return
        if (pathContextKeywords.none { it in bodyText }) return
        reportAt(
            function,
            "File upload using original fileName() as path — sanitize with UUID or allowlist of safe extensions",
        )
    }
}
