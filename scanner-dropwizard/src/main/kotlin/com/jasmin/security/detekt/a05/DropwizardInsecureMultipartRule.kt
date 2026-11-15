package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import dev.detekt.api.Config
import java.util.Properties

// OWASP A05 — Security Misconfiguration
// A very high max form data size in the Dropwizard HTTP connector enables
// resource-exhaustion attacks by uploading enormous request bodies.
// Compliant:   server.maxRequestEntitySize=10MiB
// Non-compliant: server.maxRequestEntitySize=500MiB
class DropwizardInsecureMultipartRule(config: Config) : PropertiesSecurityRule(
    config,
    id = "DropwizardInsecureMultipart",
    description = "Dropwizard maxRequestEntitySize is very large — limits resource exhaustion protection",
) {
    private val largePattern = Regex("""^(\d+)\s*(GiB|GiB|GB|MiB|MB)$""", RegexOption.IGNORE_CASE)

    private val maxBodySizeMb: Int = config.valueOrDefault("maxBodySizeMb", 50)

    @Suppress("ReturnCount")
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val key = "server.maxRequestEntitySize"
        val value = props.getProperty(key) ?: return emptyList()
        val match = largePattern.matchEntire(value.trim()) ?: return emptyList()
        val size = match.groupValues[1].toLongOrNull() ?: return emptyList()
        val unit = match.groupValues[2].uppercase()
        val mib = if ("G" in unit) size * 1024 else size
        if (mib <= maxBodySizeMb) return emptyList()
        return listOf(key to "maxRequestEntitySize=$value is very large — set a reasonable limit (e.g. 10MiB)")
    }
}
