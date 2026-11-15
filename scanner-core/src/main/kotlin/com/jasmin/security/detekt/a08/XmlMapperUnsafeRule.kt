package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A08 — Software and Data Integrity Failures
 * FindSecBugs: JACKSON_UNSAFE_DESERIALIZATION
 *
 * XmlMapper extends ObjectMapper and inherits its unsafe defaults.
 * DTD processing is enabled by default, exposing XXE vulnerabilities
 * in addition to Jackson gadget-chain deserialization risks.
 *
 * Compliant:
 *   XmlMapper().apply {
 *       configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
 *       configure(FromXmlParser.Feature.EMPTY_ELEMENT_AS_NULL, true)
 *   }
 *
 * Non-compliant:
 *   val mapper = XmlMapper()
 */
class XmlMapperUnsafeRule(config: Config) : SecurityRule(
    config,
    id = "XmlMapperUnsafe",
    description = "XmlMapper() has unsafe defaults — disable DTD and set FAIL_ON_UNKNOWN_PROPERTIES",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.XML_MAPPER_CLASS) return
        reportAt(
            expression,
            "XmlMapper() inherits Jackson unsafe defaults — configure DTD protection and type validation",
        )
    }
}
