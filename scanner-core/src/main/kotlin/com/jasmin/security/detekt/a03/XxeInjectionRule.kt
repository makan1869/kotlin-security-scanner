package com.jasmin.security.detekt.a03

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A03 — Injection (XML External Entity)
 * FindSecBugs: XXE_DTD, XXE_SAXPARSER, XXE_XMLREADER
 *
 * Flags XML factory instantiation without explicit secure-processing configuration.
 * By default these factories allow DTD processing and external entity resolution,
 * enabling file read, SSRF, and DoS attacks.
 *
 * Compliant:
 *   DocumentBuilderFactory.newInstance().also {
 *       it.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
 *   }
 *
 * Non-compliant:
 *   val dbf = DocumentBuilderFactory.newInstance()  // external entities enabled by default
 *   val parser = SAXParserFactory.newInstance().newSAXParser()
 */
class XxeInjectionRule(config: Config) : SecurityRule(
    config,
    id = "XxeInjection",
    description = "XML factory created without disabling external entity processing (XXE)",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (isUnsafeXmlFactory(expression)) {
            reportAt(
                expression,
                "XML factory enables external entities by default — disable DTD processing before use",
            )
        }
    }

    @Suppress("ReturnCount")
    private fun isUnsafeXmlFactory(expression: KtCallExpression): Boolean {
        if (expression.calleeExpression?.text != "newInstance") return false
        val receiver = (expression.parent as? KtDotQualifiedExpression)
            ?.receiverExpression?.text ?: return false
        // FQN-tolerant: javax.xml.parsers.DocumentBuilderFactory.newInstance() → DocumentBuilderFactory
        return receiver.substringAfterLast(".") in DetectionPatterns.XXE_FACTORY_CLASSES
    }
}
