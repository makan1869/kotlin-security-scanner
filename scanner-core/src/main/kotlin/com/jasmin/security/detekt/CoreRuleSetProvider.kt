package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.JaxrsOpenRedirectRule
import com.jasmin.security.detekt.a01.PredictableTempFileRule
import com.jasmin.security.detekt.a02.HardcodedAesKeyRule
import com.jasmin.security.detekt.a02.HardcodedIvRule
import com.jasmin.security.detekt.a02.HardcodedPrivateKeyRule
import com.jasmin.security.detekt.a02.InsecureRandomSeedRule
import com.jasmin.security.detekt.a02.InsecureSslContextRule
import com.jasmin.security.detekt.a02.TrustAllHostnamesRule
import com.jasmin.security.detekt.a02.InsecurePasswordStorageRule
import com.jasmin.security.detekt.a02.JwtNoneAlgorithmRule
import com.jasmin.security.detekt.a02.JwtWeakSecretRule
import com.jasmin.security.detekt.a02.TrustAllCertsRule
import com.jasmin.security.detekt.a02.UnsafeCryptoPaddingOracleRule
import com.jasmin.security.detekt.a02.WeakCipherModeRule
import com.jasmin.security.detekt.a02.WeakHashAlgorithmRule
import com.jasmin.security.detekt.a02.WeakRsaKeyRule
import com.jasmin.security.detekt.a03.CommandInjectionRule
import com.jasmin.security.detekt.a03.GroovyScriptInjectionRule
import com.jasmin.security.detekt.a03.JndiInjectionRule
import com.jasmin.security.detekt.a03.LdapInjectionRule
import com.jasmin.security.detekt.a03.PathTraversalRule
import com.jasmin.security.detekt.a03.ReflectionInjectionRule
import com.jasmin.security.detekt.a03.SqlInjectionRule
import com.jasmin.security.detekt.a03.XpathInjectionRule
import com.jasmin.security.detekt.a03.XxeInjectionRule
import com.jasmin.security.detekt.a03.ZipSlipRule
import com.jasmin.security.detekt.a06.RegexDenialOfServiceRule
import com.jasmin.security.detekt.a06.RegexInjectionRule
import com.jasmin.security.detekt.a07.GitHubTokenRule
import com.jasmin.security.detekt.a07.GoogleApiKeyRule
import com.jasmin.security.detekt.a07.HardcodedAwsCredentialsRule
import com.jasmin.security.detekt.a07.HardcodedCredentialsRule
import com.jasmin.security.detekt.a07.HardcodedJdbcCredentialsRule
import com.jasmin.security.detekt.a07.HardcodedJwtTokenRule
import com.jasmin.security.detekt.a07.InsecureRandomRule
import com.jasmin.security.detekt.a07.SlackTokenRule
import com.jasmin.security.detekt.a07.StripeSecretKeyRule
import com.jasmin.security.detekt.a08.InsecureDeserializationRule
import com.jasmin.security.detekt.a08.JacksonUnsafeDeserializationRule
import com.jasmin.security.detekt.a08.KotlinxSerializationSensitiveFieldRule
import com.jasmin.security.detekt.a08.XmlMapperUnsafeRule
import com.jasmin.security.detekt.a09.LogForgingRule
import com.jasmin.security.detekt.a09.SensitiveDataLoggingRule
import com.jasmin.security.detekt.a05.CorsWildcardOriginsRule
import com.jasmin.security.detekt.a05.InsecureFilePermissionsRule
import com.jasmin.security.detekt.a10.SsrfRule
import dev.detekt.api.RuleSet
import dev.detekt.api.RuleSetId
import dev.detekt.api.RuleSetProvider

/**
 * Framework-agnostic security rules.
 * Safe to add to any Kotlin project regardless of framework.
 *
 * To add a rule here: implement it in the matching a0X/ package,
 * then add it to the list below and to config/detekt/detekt.yml.
 * See .claude/commands/add-security-rule.md for the full guide.
 */
class CoreRuleSetProvider : RuleSetProvider {

    override val ruleSetId = RuleSetId("security-core")

    // config is the rule-set config (security-core section). Each Rule subclass
    // receives it as ruleSetConfig and self-scopes via getRuleConfig() = ruleSetConfig.subConfig(ruleId).
    override fun instance(): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            ::JaxrsOpenRedirectRule,
            ::PredictableTempFileRule,
            // A02 Cryptographic Failures
            ::HardcodedAesKeyRule,
            ::HardcodedPrivateKeyRule,
            ::InsecureRandomSeedRule,
            ::InsecureSslContextRule,
            ::TrustAllHostnamesRule,
            ::WeakCipherModeRule,
            ::WeakHashAlgorithmRule,
            ::TrustAllCertsRule,
            ::HardcodedIvRule,
            ::WeakRsaKeyRule,
            ::JwtNoneAlgorithmRule,
            ::JwtWeakSecretRule,
            ::UnsafeCryptoPaddingOracleRule,
            ::InsecurePasswordStorageRule,
            // A03 Injection
            ::SqlInjectionRule,
            ::LdapInjectionRule,
            ::JndiInjectionRule,
            ::XpathInjectionRule,
            ::ReflectionInjectionRule,
            ::PathTraversalRule,
            ::CommandInjectionRule,
            ::XxeInjectionRule,
            ::GroovyScriptInjectionRule,
            ::ZipSlipRule,
            // A06 Vulnerable Components / ReDoS
            ::RegexDenialOfServiceRule,
            ::RegexInjectionRule,
            // A07 Authentication Failures
            ::HardcodedCredentialsRule,
            ::InsecureRandomRule,
            ::HardcodedAwsCredentialsRule,
            ::GoogleApiKeyRule,
            ::SlackTokenRule,
            ::GitHubTokenRule,
            ::StripeSecretKeyRule,
            ::HardcodedJwtTokenRule,
            ::HardcodedJdbcCredentialsRule,
            // A08 Software and Data Integrity
            ::InsecureDeserializationRule,
            ::JacksonUnsafeDeserializationRule,
            ::XmlMapperUnsafeRule,
            ::KotlinxSerializationSensitiveFieldRule,
            // A05 Security Misconfiguration
            ::CorsWildcardOriginsRule,
            ::InsecureFilePermissionsRule,
            // A09 Logging Failures
            ::SensitiveDataLoggingRule,
            ::LogForgingRule,
            // A10 Server-Side Request Forgery
            ::SsrfRule,
        )
    )
}
