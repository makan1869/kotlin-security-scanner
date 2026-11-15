package com.jasmin.security.detekt.a08

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression

// OWASP A08 — Software and Data Integrity Failures
// Jsonb.fromJson(input, Any::class.java) deserializes into an arbitrary type at runtime —
// allows polymorphic deserialization attacks similar to Jackson CVE-2017-7525.
// Compliant:   Jsonb.fromJson(input, MyDto::class.java)
// Non-compliant: Jsonb.fromJson(body, Object::class.java)
class QuarkusJsonbUnsafeDeserializationRule(config: Config) : SecurityRule(
    config,
    id = "QuarkusJsonbUnsafeDeserialization",
    description = "Jsonb.fromJson() with Object/Any type — enables polymorphic deserialization attacks",
) {
    private val unsafeTypes = setOf("Object::class.java", "Any::class.java", "Serializable::class.java")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != "fromJson") return
        val args = expression.valueArguments
        if (args.size < 2) return
        val typeArg = args[1].getArgumentExpression()?.text ?: return
        if (typeArg !in unsafeTypes) return
        reportAt(
            expression,
            "Jsonb.fromJson() with $typeArg — use a concrete DTO class to prevent deserialization attacks",
        )
    }
}
