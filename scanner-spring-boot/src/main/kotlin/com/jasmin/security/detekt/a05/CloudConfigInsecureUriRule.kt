package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.PropertiesSecurityRule
import dev.detekt.api.Config
import java.util.Properties

class CloudConfigInsecureUriRule(config: Config) : PropertiesSecurityRule(
    config,
    id = "CloudConfigInsecureUri",
    description = "Spring Cloud Config URI uses HTTP — config secrets transmitted in cleartext",
) {
    override fun scanProperties(props: Properties): List<Pair<String, String>> {
        val issues = mutableListOf<Pair<String, String>>()
        props.forEach { rawKey, rawValue ->
            val key = rawKey.toString()
            val value = rawValue.toString().trim()
            if (("cloud.config.uri" in key || "cloud.config.server.git.uri" in key) &&
                value.startsWith("http://")
            ) {
                issues += key to "Config server URI uses HTTP — credentials and secrets fetched over cleartext"
            }
        }
        return issues
    }
}
