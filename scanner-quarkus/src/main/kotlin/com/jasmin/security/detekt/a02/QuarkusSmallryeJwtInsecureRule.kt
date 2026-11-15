package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.PropertiesSecurityRule
import dev.detekt.api.Config
import java.util.Properties

/**
 * OWASP A02 — Cryptographic Failures
 * mp.jwt.verify.algorithm=none disables JWT signature verification — any caller can forge tokens.
 * A hardcoded mp.jwt.verify.secret.value leaks the signing key with every artifact.
 */
class QuarkusSmallryeJwtInsecureRule(config: Config) : PropertiesSecurityRule(
    config,
    id = "QuarkusSmallryeJwtInsecure",
    description = "MicroProfile JWT misconfigured — algorithm=none or hardcoded secret",
) {
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        val algorithmKey = "mp.jwt.verify.algorithm"
        if (props.getProperty(algorithmKey)?.trim()?.uppercase() == "NONE") {
            issues += algorithmKey to "JWT algorithm=none — tokens are not verified, any caller can forge claims"
        }
        val secretKey = "mp.jwt.verify.secret.value"
        val secretValue = props.getProperty(secretKey)
        if (secretValue != null && isHardcoded(secretValue)) {
            issues += secretKey to "hardcoded JWT secret — use \${JWT_SECRET} environment variable reference"
        }
        return issues
    }

    private fun isHardcoded(value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return false
        return DetectionPatterns.SAFE_CREDENTIAL_PLACEHOLDERS.none { it.containsMatchIn(trimmed) }
    }
}
