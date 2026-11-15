package com.jasmin.security.detekt.a07

import com.jasmin.security.detekt.core.DetectionPatterns.INSECURE_RANDOM_CLASSES
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

// FindSecBugs: PREDICTABLE_RANDOM — OWASP A07
class InsecureRandomRule(config: Config = Config.empty) : SecurityRule(
    config,
    id = "InsecureRandom",
    description = "java.util.Random is not cryptographically secure — use SecureRandom for tokens and passwords",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee in INSECURE_RANDOM_CLASSES) {
            reportAt(expression, "Replace '$callee' with java.security.SecureRandom in security-sensitive contexts")
            return
        }
        // ThreadLocalRandom is only ever used as ThreadLocalRandom.current()...,
        // so the callee text is "current" — match it via the receiver class name.
        if (callee == "current") {
            val receiver = (expression.parent as? KtDotQualifiedExpression)
                ?.receiverExpression?.text?.substringAfterLast(".")
            if (receiver == "ThreadLocalRandom") {
                reportAt(
                    expression,
                    "Replace 'ThreadLocalRandom' with java.security.SecureRandom in security-sensitive contexts",
                )
            }
        }
    }
}
