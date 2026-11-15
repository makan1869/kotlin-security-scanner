package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A08 — Software and Data Integrity Failures
 * FindSecBugs: OBJECT_DESERIALIZATION
 *
 * Flags construction of ObjectInputStream and XMLDecoder.
 * Deserializing untrusted data with these classes enables remote code execution
 * through gadget chains (e.g. Apache Commons Collections, Spring Framework).
 *
 * Compliant:
 *   // Use a safe format: JSON (Jackson), Protobuf, or a filtering ObjectInputStream
 *
 * Non-compliant:
 *   val ois = ObjectInputStream(inputStream)
 *   val xd  = XMLDecoder(inputStream)
 */
class InsecureDeserializationRule(config: Config) : SecurityRule(
    config,
    id = "InsecureDeserialization",
    description = "Native Java deserialization enables RCE — use JSON/Protobuf or a filtering stream",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee in DetectionPatterns.UNSAFE_DESERIALIZERS) {
            reportAt(
                expression,
                "$callee deserializes arbitrary objects — replace with JSON/Protobuf or a ValidatingObjectInputStream",
            )
        }
    }
}
