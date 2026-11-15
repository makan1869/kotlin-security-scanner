package com.jasmin.security.detekt.a04

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtParameter

// OWASP A04 — Insecure Design
// @BeanParam binds all query/form/header params to a bean — accepting an entity class
// directly allows clients to set fields that should be server-controlled (id, role, etc.).
// Compliant:   separate DTO class that exposes only safe fields
// Non-compliant: @POST fun create(@BeanParam entity: User)
class QuarkusMassAssignmentRule(config: Config) : SecurityRule(
    config,
    id = "QuarkusMassAssignment",
    description = "@BeanParam on a POST/PUT method — mass assignment may allow role/id manipulation",
) {
    private val writeMethods = setOf("POST", "PUT", "PATCH")

    @Suppress("ReturnCount")
    override fun visitNamedFunction(function: KtNamedFunction) {
        super.visitNamedFunction(function)
        val httpMethod = function.annotationEntries
            .mapNotNull { it.shortName?.asString() }
            .firstOrNull { it in writeMethods } ?: return
        val beanParam = function.valueParameters
            .firstOrNull { it.hasBeanParamAnnotation() } ?: return
        reportAt(
            beanParam,
            "@BeanParam on @$httpMethod endpoint — use a DTO that exposes only fields the client should control",
        )
    }

    private fun KtParameter.hasBeanParamAnnotation(): Boolean =
        annotationEntries.any { it.shortName?.asString() == "BeanParam" }
}
