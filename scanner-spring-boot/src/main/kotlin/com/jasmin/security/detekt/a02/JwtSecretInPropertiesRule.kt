package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.PropertiesSecurityRule
import dev.detekt.api.Config
import java.util.Properties

/**
 * OWASP A02 — Cryptographic Failures (Hardcoded Credential)
 *
 * Storing JWT signing secrets in application.properties commits them to
 * version control and exposes them to anyone with repo access. A stolen
 * secret allows forging arbitrary tokens.
 *
 * Compliant:
 *   spring.security.oauth2.resourceserver.jwt.secret=${JWT_SECRET}
 *
 * Non-compliant:
 *   spring.security.oauth2.resourceserver.jwt.secret=mySuperSecretKey123
 */
class JwtSecretInPropertiesRule(config: Config) : PropertiesSecurityRule(
    config,
    id = "JwtSecretInProperties",
    description = "JWT signing secret stored in properties file — use environment variable or Vault",
) {
    private val sensitiveKeys = listOf(
        "spring.security.oauth2.resourceserver.jwt.secret",
        "spring.security.oauth2.resourceserver.opaquetoken.client-secret",
    )

    override fun scanProperties(props: Properties): List<Pair<String, String>> =
        sensitiveKeys.mapNotNull { key ->
            val value = props.getProperty(key) ?: return@mapNotNull null
            if (DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.any { it.containsMatchIn(value) }) return@mapNotNull null
            key to "JWT secret hardcoded in properties — use \${JWT_SECRET} and inject from environment"
        }
}
