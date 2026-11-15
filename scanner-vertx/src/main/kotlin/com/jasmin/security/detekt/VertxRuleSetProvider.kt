package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.VertxEventBusBridgeOpenRule
import com.jasmin.security.detekt.a02.VertxJwtNoneAlgorithmRule
import com.jasmin.security.detekt.a02.VertxTrustAllCertsRule
import com.jasmin.security.detekt.a03.VertxStaticHandlerRootFsRule
import com.jasmin.security.detekt.a05.VertxBodyHandlerNoLimitRule
import com.jasmin.security.detekt.a05.VertxCookieNoHttpOnlyRule
import com.jasmin.security.detekt.a05.VertxCorsWildcardRule
import com.jasmin.security.detekt.a05.VertxInsecureCookieRule
import com.jasmin.security.detekt.a05.VertxSessionCookieInsecureRule
import com.jasmin.security.detekt.a05.VertxStaticHandlerDirectoryListingRule
import com.jasmin.security.detekt.a07.VertxHardcodedJwtSecretRule
import dev.detekt.api.RuleSet
import dev.detekt.api.RuleSetId
import dev.detekt.api.RuleSetProvider

class VertxRuleSetProvider : RuleSetProvider {

    override val ruleSetId = RuleSetId("security-vertx")

    override fun instance(): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            ::VertxEventBusBridgeOpenRule,
            // A02 Cryptographic Failures
            ::VertxTrustAllCertsRule,
            ::VertxJwtNoneAlgorithmRule,
            // A03 Injection
            ::VertxStaticHandlerRootFsRule,
            // A05 Security Misconfiguration
            ::VertxCorsWildcardRule,
            ::VertxBodyHandlerNoLimitRule,
            ::VertxInsecureCookieRule,
            ::VertxCookieNoHttpOnlyRule,
            ::VertxSessionCookieInsecureRule,
            ::VertxStaticHandlerDirectoryListingRule,
            // A07 Identification and Authentication Failures
            ::VertxHardcodedJwtSecretRule,
        )
    )
}
