package com.jasmin.security.detekt

import com.jasmin.security.detekt.core.assertShippedConfigActivatesEveryRule
import org.junit.jupiter.api.Test

class SpringBootRuleSetProviderTest {

    @Test
    fun `shipped config activates every registered rule`() {
        assertShippedConfigActivatesEveryRule(SpringBootRuleSetProvider(), optIn = setOf("MissingAuthorization"))
    }
}
