package com.jasmin.security.detekt.a02

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

/**
 * OWASP A02 — Cryptographic Failures
 * FindSecBugs: WEAK_PASSWORD_ENCODER
 *
 * Flags Spring Security PasswordEncoder implementations that provide no real
 * protection: NoOpPasswordEncoder stores plaintext, Md5/ShaPasswordEncoder use
 * broken algorithms trivially reversible with rainbow tables.
 *
 * Compliant:
 *   BCryptPasswordEncoder()
 *   Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
 *
 * Non-compliant:
 *   NoOpPasswordEncoder.getInstance()
 *   Md5PasswordEncoder()
 */
class InsecurePasswordEncoderRule(config: Config) : SecurityRule(
    config,
    id = "InsecurePasswordEncoder",
    description = "Weak PasswordEncoder — use BCryptPasswordEncoder or Argon2PasswordEncoder",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (isWeakEncoderConstructor(callee) || isWeakEncoderStaticCall(expression, callee)) {
            val name = resolveEncoderName(expression, callee)
            reportAt(
                expression,
                "$name provides no real protection — use BCryptPasswordEncoder or Argon2PasswordEncoder",
            )
        }
    }

    private fun isWeakEncoderConstructor(callee: String) =
        callee in DetectionPatterns.WEAK_PASSWORD_ENCODERS

    @Suppress("ReturnCount")
    private fun isWeakEncoderStaticCall(expression: KtCallExpression, callee: String): Boolean {
        if (callee != "getInstance") return false
        val receiver = (expression.parent as? KtDotQualifiedExpression)
            ?.receiverExpression?.text ?: return false
        // Tolerate fully-qualified receivers, e.g. ...password.NoOpPasswordEncoder.getInstance().
        return receiver.substringAfterLast(".") in DetectionPatterns.WEAK_PASSWORD_ENCODERS
    }

    private fun resolveEncoderName(expression: KtCallExpression, callee: String): String {
        if (callee == "getInstance") {
            return (expression.parent as? KtDotQualifiedExpression)
                ?.receiverExpression?.text?.substringAfterLast(".") ?: callee
        }
        return callee
    }
}
