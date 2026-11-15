package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import dev.detekt.api.Config
import java.util.Properties

/**
 * OWASP A05 — Security Misconfiguration
 * Quarkus Dev Services spins up in-process databases and brokers automatically.
 * Leaving them enabled in production exposes internal infrastructure to attackers.
 */
class QuarkusDevServicesInProdRule(config: Config) : PropertiesSecurityRule(
    config,
    id = "QuarkusDevServicesInProd",
    description = "Quarkus Dev Services enabled — exposes internal infrastructure in production",
) {
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        val prodKey = "%prod.quarkus.devservices.enabled"
        val defaultKey = "quarkus.devservices.enabled"
        if (props.getProperty(prodKey) == "true") {
            issues += prodKey to "Dev Services enabled in %prod profile — set to false for production"
        }
        if (props.getProperty(defaultKey) == "true") {
            issues += defaultKey to "Dev Services enabled — add %prod.quarkus.devservices.enabled=false"
        }
        return issues
    }
}
