package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.DropwizardMissingAuthRule
import com.jasmin.security.detekt.a02.DropwizardUnencryptedJwtSecretRule
import com.jasmin.security.detekt.a02.InsecureTlsProtocolRule
import com.jasmin.security.detekt.a03.DropwizardJdbiSqlInjectionRule
import com.jasmin.security.detekt.a03.DropwizardMissingBeanValidationRule
import com.jasmin.security.detekt.a03.DropwizardSelfValidatingELRule
import com.jasmin.security.detekt.a03.DropwizardXssResponseRule
import com.jasmin.security.detekt.a05.DropwizardAdminConnectorExposedRule
import com.jasmin.security.detekt.a05.DropwizardInsecureMultipartRule
import com.jasmin.security.detekt.a05.InsecureCookieRule
import com.jasmin.security.detekt.a07.DropwizardDatabasePasswordRule
import com.jasmin.security.detekt.a07.DropwizardHardcodedTokenRule
import com.jasmin.security.detekt.a08.DropwizardJacksonPolymorphismRule
import com.jasmin.security.detekt.a09.DropwizardSensitiveDataLoggingRule
import dev.detekt.api.RuleSet
import dev.detekt.api.RuleSetId
import dev.detekt.api.RuleSetProvider

class DropwizardRuleSetProvider : RuleSetProvider {

    override val ruleSetId = RuleSetId("security-dropwizard")

    override fun instance(): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            ::DropwizardMissingAuthRule,
            // A02 Cryptographic Failures
            ::InsecureTlsProtocolRule,
            ::DropwizardUnencryptedJwtSecretRule,
            // A03 Injection
            ::DropwizardSelfValidatingELRule,
            ::DropwizardJdbiSqlInjectionRule,
            ::DropwizardMissingBeanValidationRule,
            ::DropwizardXssResponseRule,
            // A05 Security Misconfiguration
            ::InsecureCookieRule,
            ::DropwizardAdminConnectorExposedRule,
            ::DropwizardInsecureMultipartRule,
            // A07 Identification and Authentication Failures
            ::DropwizardHardcodedTokenRule,
            ::DropwizardDatabasePasswordRule,
            // A08 Software and Data Integrity Failures
            ::DropwizardJacksonPolymorphismRule,
            // A09 Security Logging and Monitoring Failures
            ::DropwizardSensitiveDataLoggingRule,
        )
    )
}
