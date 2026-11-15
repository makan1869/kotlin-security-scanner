package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.PropertiesSecurityRule
import dev.detekt.api.Config
import java.util.Properties

/**
 * OWASP A07 — Identification and Authentication Failures
 * A hardcoded quarkus.datasource.password leaks the database credential
 * with every build artifact and source-code checkout.
 */
class QuarkusHardcodedDatasourcePasswordRule(config: Config) : PropertiesSecurityRule(
    config,
    id = "QuarkusHardcodedDatasourcePassword",
    description = "quarkus.datasource.password hardcoded — use environment variable reference",
) {
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val key = "quarkus.datasource.password"
        val value = props.getProperty(key) ?: return emptyList()
        return if (isHardcoded(value)) {
            listOf(key to "hardcoded datasource password — use \${DB_PASSWORD} environment variable")
        } else {
            emptyList()
        }
    }

    private fun isHardcoded(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return false
        return DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.none { it.containsMatchIn(trimmed) }
    }
}
