package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.PropertiesSecurityRule
import dev.detekt.api.Config
import java.util.Properties

class HardcodedDatasourcePasswordRule(config: Config) : PropertiesSecurityRule(
    config,
    id = "HardcodedDatasourcePassword",
    description = "Database password hardcoded in application.properties — use environment variable",
) {
    private val passwordKeys = listOf(
        "spring.datasource.password",
        "spring.datasource.hikari.password",
        "spring.r2dbc.password",
        "spring.jpa.properties.hibernate.connection.password",
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> =
        passwordKeys.mapNotNull { key ->
            val value = props.getProperty(key) ?: return@mapNotNull null
            if (DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.any { it.containsMatchIn(value) }) return@mapNotNull null
            key to "Database password hardcoded — use \${DB_PASSWORD} and set via environment"
        }
}
