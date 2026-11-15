package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.AsyncSecurityContextLossRule
import com.jasmin.security.detekt.a01.CoroutineSecurityContextLossRule
import com.jasmin.security.detekt.a01.CsrfTokenLeakRule
import com.jasmin.security.detekt.a01.DisabledHttpSecurityRule
import com.jasmin.security.detekt.a01.FeignClientInsecureUrlRule
import com.jasmin.security.detekt.a01.MissingAuthorizationRule
import com.jasmin.security.detekt.a01.OpenRedirectRule
import com.jasmin.security.detekt.a01.PermitAllAdminPathRule
import com.jasmin.security.detekt.a01.ReactivePermitAllExchangeRule
import com.jasmin.security.detekt.a01.ReactiveSecurityContextHolderRule
import com.jasmin.security.detekt.a01.UnvalidatedForwardRule
import com.jasmin.security.detekt.a02.InsecurePasswordEncoderRule
import com.jasmin.security.detekt.a02.InsecureRedisConnectionRule
import com.jasmin.security.detekt.a02.InsecureSmtpConfigRule
import com.jasmin.security.detekt.a02.JwtExpirationMissingRule
import com.jasmin.security.detekt.a02.JwtSecretInPropertiesRule
import com.jasmin.security.detekt.a02.MissingHttpsRedirectRule
import com.jasmin.security.detekt.a02.OAuth2ClientSecretInPropertiesRule
import com.jasmin.security.detekt.a02.SpringCacheableSensitiveRule
import com.jasmin.security.detekt.a02.WeakBcryptRoundsRule
import com.jasmin.security.detekt.a03.ELInjectionRule
import com.jasmin.security.detekt.a03.EntityManagerJpqlInjectionRule
import com.jasmin.security.detekt.a03.ResponseSplittingRule
import com.jasmin.security.detekt.a03.SpelInjectionRule
import com.jasmin.security.detekt.a03.SpringDataMongoInjectionRule
import com.jasmin.security.detekt.a03.SpringDataSortInjectionRule
import com.jasmin.security.detekt.a03.ThymeleafSSTIRule
import com.jasmin.security.detekt.a04.MassAssignmentRule
import com.jasmin.security.detekt.a05.CloudConfigInsecureUriRule
import com.jasmin.security.detekt.a05.CrossOriginCredentialsWildcardRule
import com.jasmin.security.detekt.a05.ExceptionDetailsExposedRule
import com.jasmin.security.detekt.a05.H2ConsoleEnabledRule
import com.jasmin.security.detekt.a05.HttpMethodOverrideRule
import com.jasmin.security.detekt.a05.InsecureActuatorExposureRule
import com.jasmin.security.detekt.a05.KafkaInsecureProtocolRule
import com.jasmin.security.detekt.a05.KafkaTrustedPackagesWildcardRule
import com.jasmin.security.detekt.a05.PermissiveCorsRule
import com.jasmin.security.detekt.a05.SecurityHeadersMissingRule
import com.jasmin.security.detekt.a05.SpringActuatorShutdownEnabledRule
import com.jasmin.security.detekt.a05.SpringBootCookieNotHttpOnlyRule
import com.jasmin.security.detekt.a05.SpringBootInsecureFileUploadRule
import com.jasmin.security.detekt.a05.SpringContentTypeOptionsDisabledRule
import com.jasmin.security.detekt.a05.SpringCsrfDisabledRule
import com.jasmin.security.detekt.a05.SpringCsrfIgnoringMatchersRule
import com.jasmin.security.detekt.a05.SpringFrameOptionsDisabledRule
import com.jasmin.security.detekt.a05.SpringSecurityDebugEnabledRule
import com.jasmin.security.detekt.a05.SpringSessionFixationNoneRule
import com.jasmin.security.detekt.a05.WebFluxBlockingCallRule
import com.jasmin.security.detekt.a02.WebClientInsecureSslRule
import com.jasmin.security.detekt.a07.HardcodedDatasourcePasswordRule
import com.jasmin.security.detekt.a07.InsecureRememberMeRule
import com.jasmin.security.detekt.a07.SpringBootHardcodedValueDefaultRule
import com.jasmin.security.detekt.a07.SpringBootNoOpPasswordEncoderRule
import com.jasmin.security.detekt.a08.SpringBootRequestBodyAnyTypeRule
import com.jasmin.security.detekt.a09.SecurityLoggingVerboseRule
import com.jasmin.security.detekt.a09.ShowSqlEnabledRule
import com.jasmin.security.detekt.a09.SpringBootExceptionBodyLeakRule
import com.jasmin.security.detekt.a10.RestTemplateSsrfRule
import com.jasmin.security.detekt.a10.WebClientSSRFRule
import dev.detekt.api.RuleSet
import dev.detekt.api.RuleSetId
import dev.detekt.api.RuleSetProvider

/**
 * Spring Boot specific security rules.
 * Catches Spring Security misconfigurations and missing access control
 * on Spring MVC / Spring WebFlux endpoints.
 */
class SpringBootRuleSetProvider : RuleSetProvider {

    override val ruleSetId = RuleSetId("security-spring-boot")

    override fun instance(): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            ::MissingAuthorizationRule,
            ::ReactiveSecurityContextHolderRule,
            ::ReactivePermitAllExchangeRule,
            ::OpenRedirectRule,
            ::DisabledHttpSecurityRule,
            ::CsrfTokenLeakRule,
            ::CoroutineSecurityContextLossRule,
            ::AsyncSecurityContextLossRule,
            ::FeignClientInsecureUrlRule,
            ::UnvalidatedForwardRule,
            ::PermitAllAdminPathRule,
            // A02 Cryptographic Failures
            ::InsecurePasswordEncoderRule,
            ::WebClientInsecureSslRule,
            ::WeakBcryptRoundsRule,
            ::JwtExpirationMissingRule,
            ::JwtSecretInPropertiesRule,
            ::OAuth2ClientSecretInPropertiesRule,
            ::SpringCacheableSensitiveRule,
            ::MissingHttpsRedirectRule,
            ::InsecureRedisConnectionRule,
            ::InsecureSmtpConfigRule,
            // A03 Injection
            ::SpelInjectionRule,
            ::ResponseSplittingRule,
            ::ELInjectionRule,
            ::SpringDataMongoInjectionRule,
            ::ThymeleafSSTIRule,
            ::EntityManagerJpqlInjectionRule,
            ::SpringDataSortInjectionRule,
            // A04 Insecure Design
            ::MassAssignmentRule,
            // A05 Security Misconfiguration
            ::SpringCsrfDisabledRule,
            ::PermissiveCorsRule,
            ::InsecureActuatorExposureRule,
            ::SecurityHeadersMissingRule,
            ::ExceptionDetailsExposedRule,
            ::HttpMethodOverrideRule,
            ::KafkaTrustedPackagesWildcardRule,
            ::KafkaInsecureProtocolRule,
            ::SpringSecurityDebugEnabledRule,
            ::H2ConsoleEnabledRule,
            ::SpringActuatorShutdownEnabledRule,
            ::CloudConfigInsecureUriRule,
            ::CrossOriginCredentialsWildcardRule,
            ::SpringBootCookieNotHttpOnlyRule,
            ::SpringBootInsecureFileUploadRule,
            ::SpringFrameOptionsDisabledRule,
            ::WebFluxBlockingCallRule,
            ::SpringContentTypeOptionsDisabledRule,
            ::SpringSessionFixationNoneRule,
            ::SpringCsrfIgnoringMatchersRule,
            // A07 Identification and Authentication Failures
            ::InsecureRememberMeRule,
            ::HardcodedDatasourcePasswordRule,
            ::SpringBootNoOpPasswordEncoderRule,
            ::SpringBootHardcodedValueDefaultRule,
            // A08 Software and Data Integrity Failures
            ::SpringBootRequestBodyAnyTypeRule,
            // A09 Security Logging and Monitoring Failures
            ::ShowSqlEnabledRule,
            ::SecurityLoggingVerboseRule,
            ::SpringBootExceptionBodyLeakRule,
            // A10 Server-Side Request Forgery
            ::WebClientSSRFRule,
            ::RestTemplateSsrfRule,
        )
    )
}
