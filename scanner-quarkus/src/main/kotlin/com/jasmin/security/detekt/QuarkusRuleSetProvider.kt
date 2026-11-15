package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.QuarkusCacheResultSensitiveRule
import com.jasmin.security.detekt.a01.QuarkusFormCsrfMissingRule
import com.jasmin.security.detekt.a01.QuarkusGraphQLNoAuthRule
import com.jasmin.security.detekt.a01.QuarkusJsonBeforeAuthRule
import com.jasmin.security.detekt.a01.QuarkusMissingAuthRule
import com.jasmin.security.detekt.a01.QuarkusPermitAllSensitiveRule
import com.jasmin.security.detekt.a01.QuarkusReactiveRouteNoAuthRule
import com.jasmin.security.detekt.a01.QuarkusRestClientInsecureUrlRule
import com.jasmin.security.detekt.a01.QuarkusSystemExitRule
import com.jasmin.security.detekt.a01.QuarkusUnsafeSecurityContextRule
import com.jasmin.security.detekt.a02.QuarkusGrpcInsecureRule
import com.jasmin.security.detekt.a02.QuarkusMongoInsecureRule
import com.jasmin.security.detekt.a02.QuarkusOidcAudienceMissingRule
import com.jasmin.security.detekt.a02.QuarkusRedisInsecureRule
import com.jasmin.security.detekt.a02.QuarkusSmallryeJwtInsecureRule
import com.jasmin.security.detekt.a03.PanacheRawQueryRule
import com.jasmin.security.detekt.a03.QuarkusMissingBeanValidationRule
import com.jasmin.security.detekt.a03.QuarkusNativeQueryInjectionRule
import com.jasmin.security.detekt.a03.QuarkusPathParamInjectionRule
import com.jasmin.security.detekt.a03.QuarkusSensitiveQueryParamRule
import com.jasmin.security.detekt.a04.QuarkusMassAssignmentRule
import com.jasmin.security.detekt.a05.QuarkusBuildTimeSecretLeakRule
import com.jasmin.security.detekt.a05.QuarkusCorsPermissiveConfigRule
import com.jasmin.security.detekt.a05.QuarkusDevServicesInProdRule
import com.jasmin.security.detekt.a05.QuarkusInsecureCookieRule
import com.jasmin.security.detekt.a05.QuarkusInsecureFileUploadRule
import com.jasmin.security.detekt.a05.QuarkusMultipartInsecureRule
import com.jasmin.security.detekt.a05.QuarkusSmallRyeHealthInsecureRule
import com.jasmin.security.detekt.a05.QuarkusSwaggerUiInProdRule
import com.jasmin.security.detekt.a05.QuarkusUnsafeHeaderRule
import com.jasmin.security.detekt.a07.QuarkusConfigPasswordLeakRule
import com.jasmin.security.detekt.a07.QuarkusHardcodedConfigPropertyDefaultRule
import com.jasmin.security.detekt.a07.QuarkusHardcodedConfigSecretRule
import com.jasmin.security.detekt.a07.QuarkusHardcodedDatasourcePasswordRule
import com.jasmin.security.detekt.a07.QuarkusOidcInsecureConfigRule
import com.jasmin.security.detekt.a08.QuarkusJsonbUnsafeDeserializationRule
import com.jasmin.security.detekt.a08.QuarkusReflectionUnsafeRule
import com.jasmin.security.detekt.a09.QuarkusExceptionMessageLeakRule
import com.jasmin.security.detekt.a09.QuarkusPasswordInLogRule
import dev.detekt.api.RuleSet
import dev.detekt.api.RuleSetId
import dev.detekt.api.RuleSetProvider

class QuarkusRuleSetProvider : RuleSetProvider {

    override val ruleSetId = RuleSetId("security-quarkus")

    override fun instance(): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            ::QuarkusMissingAuthRule,
            ::QuarkusSystemExitRule,
            ::QuarkusPermitAllSensitiveRule,
            ::QuarkusJsonBeforeAuthRule,
            ::QuarkusRestClientInsecureUrlRule,
            ::QuarkusGraphQLNoAuthRule,
            ::QuarkusReactiveRouteNoAuthRule,
            ::QuarkusFormCsrfMissingRule,
            ::QuarkusUnsafeSecurityContextRule,
            ::QuarkusCacheResultSensitiveRule,
            // A02 Cryptographic Failures
            ::QuarkusSmallryeJwtInsecureRule,
            ::QuarkusRedisInsecureRule,
            ::QuarkusMongoInsecureRule,
            ::QuarkusOidcAudienceMissingRule,
            ::QuarkusGrpcInsecureRule,
            // A03 Injection
            ::PanacheRawQueryRule,
            ::QuarkusMissingBeanValidationRule,
            ::QuarkusNativeQueryInjectionRule,
            ::QuarkusPathParamInjectionRule,
            ::QuarkusSensitiveQueryParamRule,
            // A04 Insecure Design
            ::QuarkusMassAssignmentRule,
            // A05 Security Misconfiguration
            ::QuarkusUnsafeHeaderRule,
            ::QuarkusBuildTimeSecretLeakRule,
            ::QuarkusCorsPermissiveConfigRule,
            ::QuarkusDevServicesInProdRule,
            ::QuarkusMultipartInsecureRule,
            ::QuarkusSmallRyeHealthInsecureRule,
            ::QuarkusSwaggerUiInProdRule,
            ::QuarkusInsecureCookieRule,
            ::QuarkusInsecureFileUploadRule,
            // A07 Identification and Authentication Failures
            ::QuarkusHardcodedConfigSecretRule,
            ::QuarkusOidcInsecureConfigRule,
            ::QuarkusHardcodedDatasourcePasswordRule,
            ::QuarkusConfigPasswordLeakRule,
            ::QuarkusHardcodedConfigPropertyDefaultRule,
            // A08 Software and Data Integrity
            ::QuarkusReflectionUnsafeRule,
            ::QuarkusJsonbUnsafeDeserializationRule,
            // A09 Security Logging and Monitoring Failures
            ::QuarkusExceptionMessageLeakRule,
            ::QuarkusPasswordInLogRule,
        )
    )
}
