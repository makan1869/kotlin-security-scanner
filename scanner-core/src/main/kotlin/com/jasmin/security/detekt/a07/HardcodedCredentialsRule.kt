package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns.CREDENTIAL_NAME_PHRASES
import com.jasmin.security.detekt.core.DetectionPatterns.CREDENTIAL_NAME_SUFFIXES
import com.jasmin.security.detekt.core.DetectionPatterns.CREDENTIAL_NAME_WORDS
import com.jasmin.security.detekt.core.DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: HARD_CODE_PASSWORD — OWASP A07
class HardcodedCredentialsRule(config: Config = Config.empty) : SecurityRule(
    config,
    id = "HardcodedCredentials",
    description = "Hardcoded credential detected — move secrets to environment variables or a vault",
) {
    companion object {
        private const val MIN_CREDENTIAL_LENGTH = 3
        private val NAME_WORD_BOUNDARY = Regex("(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|[_\\-.\\s]+")
    }

    @Suppress("ReturnCount")
    override fun visitProperty(property: KtProperty) {
        super.visitProperty(property)
        val name = property.name ?: return
        if (!looksLikeCredentialVariable(name)) return

        val value = (property.initializer as? KtStringTemplateExpression) ?: return
        if (value.isLiteral() && isSuspiciousValue(value.rawValue())) {
            reportAt(property, "Variable '${property.name}' appears to contain a hardcoded credential")
        }
    }

    private fun looksLikeCredentialVariable(name: String): Boolean {
        val words =
            name.split(NAME_WORD_BOUNDARY)
                .filter(String::isNotEmpty)
                .map(String::lowercase)
                .dropLastWhile { it in CREDENTIAL_NAME_SUFFIXES }
        return words.lastOrNull() in CREDENTIAL_NAME_WORDS || words.takeLast(2) in CREDENTIAL_NAME_PHRASES
    }

    private fun isSuspiciousValue(value: String) =
        value.length >= MIN_CREDENTIAL_LENGTH && SAFE_CREDENTIAL_PLACEHOLDERS.none { it.containsMatchIn(value) }
}
