package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A05 — Security Misconfiguration (MIME Sniffing / CWE-693)
 *
 * Disabling X-Content-Type-Options lets browsers MIME-sniff responses, which can turn
 * a user-uploaded file into executable script. Spring sends "nosniff" by default;
 * contentTypeOptions { disable() } removes it.
 *
 * Non-compliant:
 *   http.headers { contentTypeOptions { disable() } }
 */
class SpringContentTypeOptionsDisabledRule(config: Config = Config.empty) : SecurityRule(
    config,
    id = "SpringContentTypeOptionsDisabled",
    description = "X-Content-Type-Options disabled — browsers may MIME-sniff responses",
) {
    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        val disabled = when (callee) {
            "contentTypeOptions" -> expression.lambdaArguments.any { it.text.contains("disable") } ||
                expression.valueArguments.any { it.text.contains("disable") }
            "disable" -> (expression.parent as? KtDotQualifiedExpression)
                ?.receiverExpression?.text?.contains("contentTypeOptions") == true
            else -> false
        }
        if (disabled) {
            reportAt(expression, "contentTypeOptions disabled — keep the nosniff header enabled")
        }
    }
}
