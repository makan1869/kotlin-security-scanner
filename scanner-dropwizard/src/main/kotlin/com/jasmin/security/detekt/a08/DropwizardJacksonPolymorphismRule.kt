package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A08 — Software and Data Integrity Failures (Jackson Polymorphic Deserialization)
// ObjectMapper.enableDefaultTyping() is a known vector for RCE via deserialization gadgets
// (CVE-2017-7525, CVE-2019-14379 and many related CVEs).
// Compliant:   mapper.activateDefaultTypingAsProperty(validator, OBJECT_AND_NON_CONCRETE, "@class")
// Non-compliant: mapper.enableDefaultTyping()
class DropwizardJacksonPolymorphismRule(config: Config) : SecurityRule(
    config,
    id = "DropwizardJacksonPolymorphism",
    description = "ObjectMapper.enableDefaultTyping() enables RCE via deserialization gadgets (CVE-2017-7525)",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee != "enableDefaultTyping") return
        reportAt(
            expression,
            "enableDefaultTyping() allows attacker-controlled class loading — use activateDefaultTypingAsProperty()",
        )
    }
}
