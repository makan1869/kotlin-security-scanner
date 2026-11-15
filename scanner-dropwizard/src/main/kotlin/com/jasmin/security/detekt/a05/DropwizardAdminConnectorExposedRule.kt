package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import dev.detekt.api.Config
import java.util.Properties

// OWASP A05 — Security Misconfiguration
// Dropwizard's admin connector bound to 0.0.0.0 exposes /admin endpoints
// (thread dump, metrics, healthchecks, tasks) to all network interfaces.
// Compliant:   server.adminConnectors[0].bindHost=127.0.0.1
// Non-compliant: server.adminConnectors[0].bindHost=0.0.0.0
class DropwizardAdminConnectorExposedRule(config: Config) : PropertiesSecurityRule(
    config,
    id = "DropwizardAdminConnectorExposed",
    description = "Dropwizard admin connector bound to 0.0.0.0 — /admin endpoints exposed publicly",
) {
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            if ("adminConnectors" in key && "bindHost" in key && value == "0.0.0.0") {
                issues += key to "Admin connector bound to 0.0.0.0 — set bindHost=127.0.0.1"
            }
        }
        return issues
    }
}
