package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

// OWASP A05 — Security Misconfiguration
// SchemaUtils.create/drop in application boot code runs DDL on every startup.
// Exposes the schema structure via error messages and risks data loss on drop.
// Compliant:   use database migrations (Flyway/Liquibase) in a dedicated migration step
// Non-compliant: SchemaUtils.create(Users, Orders) in Application.module()
class KtorExposedSchemaAutoCreateRule(config: Config) : SecurityRule(
    config,
    id = "KtorExposedSchemaAutoCreate",
    description = "SchemaUtils.create/drop in application code — use Flyway or Liquibase migrations instead",
) {
    private val dangerousMethods = setOf("create", "drop", "createMissingTablesAndColumns", "dropDatabase")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        val callee = expression.calleeExpression?.text ?: return
        if (callee !in dangerousMethods) return
        val parent = expression.parent as? KtDotQualifiedExpression ?: return
        if (parent.receiverExpression.text != "SchemaUtils") return
        reportAt(
            expression,
            "SchemaUtils.$callee() in application code — replace with versioned migrations (Flyway/Liquibase)",
        )
    }
}
