package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

/**
 * OWASP A07 — Identification and Authentication Failures
 *
 * String literals matching the Google / Firebase / GCP API key format ("AIza"
 * followed by 35 url-safe characters) are live credentials. Once committed they
 * remain in git history permanently and must be rotated in the Cloud Console.
 *
 * Non-compliant:
 *   val key = "AIzaSyD-1234567890abcdefghijklmnopqrstuv"
 */
class GoogleApiKeyRule(config: Config) : SecurityRule(
    config,
    id = "GoogleApiKey",
    description = "Hardcoded Google/Firebase API key — rotate it and load from a secret manager",
) {
    override fun visitStringTemplateExpression(expression: KtStringTemplateExpression) {
        super.visitStringTemplateExpression(expression)
        if (expression.hasInterpolation()) return
        val text = expression.entries.joinToString("") { it.text }
        if (DetectionPatterns.GOOGLE_API_KEY_PATTERN.containsMatchIn(text)) {
            reportAt(
                expression,
                "Hardcoded Google API key detected — rotate it and load from environment or a secret manager",
            )
        }
    }
}
