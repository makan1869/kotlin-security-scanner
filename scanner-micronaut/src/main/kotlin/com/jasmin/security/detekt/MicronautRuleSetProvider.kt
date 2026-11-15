package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.MicronautAnonymousAccessRule
import com.jasmin.security.detekt.a01.MicronautCacheableSensitiveRule
import com.jasmin.security.detekt.a01.MicronautMissingSecuredRule
import com.jasmin.security.detekt.a01.MicronautRetryOnAuthRule
import com.jasmin.security.detekt.a01.MicronautWebSocketNoAuthRule
import com.jasmin.security.detekt.a02.MicronautGrpcInsecureRule
import com.jasmin.security.detekt.a02.MicronautInsecureHttpClientRule
import com.jasmin.security.detekt.a03.MicronautSensitiveQueryParamRule
import com.jasmin.security.detekt.a04.MicronautBodyAnyTypeRule
import com.jasmin.security.detekt.a05.MicronautInsecureCookieRule
import com.jasmin.security.detekt.a05.MicronautManagementEndpointInsecureRule
import com.jasmin.security.detekt.a07.MicronautHardcodedSecretRule
import com.jasmin.security.detekt.a09.MicronautExceptionMessageLeakRule
import dev.detekt.api.RuleSet
import dev.detekt.api.RuleSetId
import dev.detekt.api.RuleSetProvider

class MicronautRuleSetProvider : RuleSetProvider {

    override val ruleSetId = RuleSetId("security-micronaut")

    override fun instance(): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            ::MicronautMissingSecuredRule,
            ::MicronautWebSocketNoAuthRule,
            ::MicronautCacheableSensitiveRule,
            ::MicronautRetryOnAuthRule,
            ::MicronautAnonymousAccessRule,
            // A02 Cryptographic Failures
            ::MicronautInsecureHttpClientRule,
            ::MicronautGrpcInsecureRule,
            // A03 Injection
            ::MicronautSensitiveQueryParamRule,
            // A04 Insecure Design
            ::MicronautBodyAnyTypeRule,
            // A05 Security Misconfiguration
            ::MicronautManagementEndpointInsecureRule,
            ::MicronautInsecureCookieRule,
            // A07 Identification and Authentication Failures
            ::MicronautHardcodedSecretRule,
            // A09 Security Logging and Monitoring Failures
            ::MicronautExceptionMessageLeakRule,
        )
    )
}
